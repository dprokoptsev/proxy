/**
 * main.cpp -- a main entry point
 *
 * This file is part of a tiny socks5 proxy server.
 *
 * Copyright (c) 2018 Dmitry Prokoptsev <dprokoptsev@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "log.h"
#include <syncio/syncio.h>
#include <fstream>
#include <set>
#include <getopt.h>

std::string readstr(std::istream& s, size_t sz)
{
	std::vector<char> buf(sz);
	if (s.read(&buf[0], sz))
		return std::string(&buf[0], sz);
	else
		return std::string();
}

std::string readpfxstr(std::istream& s)
{
	ssize_t len = s.get();
	return s ? readstr(s, len) : std::string();
}

typedef std::set<std::pair<std::string, std::string>> Secrets;

Secrets g_secrets;

Secrets read_secrets(const std::string& filename)
{
	Secrets ret;
	std::ifstream f(filename);
	std::string user, passwd;
	while (f >> user >> passwd)
		ret.insert(std::make_pair(user, passwd));
	return ret;
}

bool auth(const std::string& username, const std::string& passwd)
{
	return g_secrets.find(std::make_pair(username, passwd)) != g_secrets.end();
}

void write_addr(std::ostream& s, const io::addr& addr)
{
	if (addr.af() == AF_INET) {
		const struct sockaddr_in& sa = *addr.as<struct sockaddr_in>();
		s.put(0x01);
		s.write((const char*) &sa.sin_addr, 4);
		s.write((const char*) &sa.sin_port, 2);
	} else if (addr.af() == AF_INET6) {
		const struct sockaddr_in6& sa = *addr.as<struct sockaddr_in6>();
		s.put(0x04);
		s.write((const char*) &sa.sin6_addr, 16);
		s.write((const char*) &sa.sin6_port, 2);
	} else {
		throw std::runtime_error("unknown address family");
	}
}

io::addr read_addr(std::istream& s)
{
	union {
		struct sockaddr addr;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	} u;
	int addrlen = 0;
	memset(&u, 0, sizeof(u));

	int family = s.get();
	if (family == 0x01) { // IPv4
		addrlen = sizeof(u.ipv4);
		u.ipv4.sin_family = AF_INET;
		s.read((char*) &u.ipv4.sin_addr, 4);
		s.read((char*) &u.ipv4.sin_port, 2);
	} else if (family == 0x04) { // IPv6
		addrlen = sizeof(u.ipv6);
		u.ipv6.sin6_family = AF_INET6;
		s.read((char*) &u.ipv6.sin6_addr, 16);
		s.read((char*) &u.ipv6.sin6_port, 2);
	} else if (family == 0x03) {
		std::string host = readpfxstr(s);
		uint16_t port = 0;
		s.read((char*) &port, 2);
		auto addrs = io::resolve(host, std::to_string(ntohs(port)));
		if (addrs.empty())
			throw std::runtime_error("cannot resolve " + host);
		else
			return addrs.front();
	}

	if (s)
		return io::addr(u.addr.sa_family, SOCK_STREAM, IPPROTO_TCP, &u.addr, addrlen);
	else
		throw std::runtime_error("cannot read net addr");
}

class NonOwningBackend: public io::stream::backend {
public:
	NonOwningBackend(io::fd& fd): fd_(&fd) {}
	ssize_t read(void* data, size_t size) override { return fd_->read(data, size); }
	ssize_t write(const void* data, size_t size) override { return fd_->write(data, size); }
	const io::fd* fd() const override { return fd_; }
private:
	io::fd* fd_;
};


io::fd negotiate(io::fd& fd)
{
	std::unique_ptr<io::stream::backend> backend;
	backend.reset(new NonOwningBackend(fd));
	io::stream s(std::move(backend));

	if (s.get() != 0x05)
		throw std::runtime_error("protocol violation (bad protocol version)");
	int method_count = s.get();
	bool has_user_passwd = false;
	while (method_count--) {
		int method = s.get();
		has_user_passwd = (method == 0x02);
	}
	if (!has_user_passwd)
		throw std::runtime_error("protocol not supported");
		
	s.write("\x05\x02", 2) << std::flush;

	int ver = s.get();
	if (ver != 0x01)	
		throw std::runtime_error("protocol violation (bad protocol version)");
	std::string username = readpfxstr(s);
	std::string passwd = readpfxstr(s);
	if (auth(username, passwd)) {
		s.write("\x01\x00", 2) << std::flush;
		DEBUG(1) << "Authenticated";
	} else {
		s.write("\x01\x01", 2) << std::flush;
		throw std::runtime_error("unauthorized");
	}

	ver = s.get();
	if (ver != 0x05)
		throw std::runtime_error("protocol violation");
	int cmd = s.get();
	if (s.get() != 0x00)
		throw std::runtime_error("protocol violation");
	
	io::addr addr = read_addr(s);

	if (cmd == 0x01) {
		INFO() << s.fd()->getsockname() << " requested a connection to " << addr;
		io::fd ret = io::connect(addr);
		s.write("\x05\x00\x00", 3);
		write_addr(s, ret.getsockname());
		s << std::flush;
		return ret;
	} else {
		WARN() << "Unsupported operation: " << cmd;
		throw std::runtime_error("unsupported operation");
	}
}

void handle_connection(io::fd fd)
{
	try {
		io::task<io::fd> neg = io::spawn(negotiate, fd);
		io::wait(neg, 5_s);
		if (!neg.completed()) {
			neg.cancel();
			return;
		}

		io::fd frontend = neg.get();
		DEBUG(1) << "Negotiation complete; entering forwarding mode";

		auto fwd = [](io::fd& from, io::fd& to, size_t& counter, io::task<void>& peer) {
			std::vector<char> buf(4096);
			for (;;) {
				size_t sz = from.read(&buf[0], buf.size());
				if (sz > 0) {
					to.write(&buf[0], sz);
					counter += sz;
				} else {
					peer.cancel();
					break;
				}
			}
		};
		io::task<void> t1, t2;
		size_t sent = 0, rcvd = 0;
		t1 = io::spawn([&]{ fwd(fd, frontend, sent, t2); });
		t2 = io::spawn([&]{ fwd(frontend, fd, rcvd, t1); });
		io::wait_all(t1, t2);
		INFO() << "Closing the connection from " << fd.getpeername()
		       << " (sent " << sent << "; rcvd " << rcvd << " bytes)";
	}
	catch (std::exception& e) {
		WARN() << e.what();
	}
}


void listener(io::addr where)
{
	io::fd fd;

	try {
		INFO() << "Listening on " << where;
		fd = io::listen(where);
	}
	catch (std::exception& e) {
		WARN() << "Cannot listen on " << where << ": " << e.what();
		return;
	}

	for (;;) {
		try {
			io::fd fd2 = fd.accept();
			INFO() << "Accepted a connection from " << fd2.getsockname();
			if (fd2)
				io::spawn(&handle_connection, std::move(fd2)).detach();
		}
		catch (std::exception& e) {
			WARN() << "Cannot accept on fd " << fd.get() << ": " << e.what();
		}
	}
}

void usage()
{
	std::cerr << "Usage: proxy -l <addr> -s <secrets_file> [-L <logfile> | -S <syslog_ident>\n"
	          << "\n"
	          << "  -l <addr>          Address to listen on\n"
	          << "  -s <secrets_file>  File with shared secrets for authenticated users\n"
		  << "  -L <logfile>       Write logs to this file\n"
		  << "  -S <ident>         Send logs to syslog with this identifier\n";
	exit(1);
}

int main(int argc, char** argv)
{
	std::vector<std::string> addrs;

	int opt;
	while ((opt = getopt(argc, argv, "s:l:L:S:")) != -1) {
		if (opt == 's') {
			g_secrets = read_secrets(optarg);
		} else if (opt == 'l') {
			addrs.push_back(optarg);
		} else if (opt == 'L') {
			Logger::instance() = new LogToFile(0, optarg);
		} else if (opt == 'S') {
			Logger::instance() = new LogToSyslog(0, optarg);
		} else {
			usage();
		}
	}
	if (addrs.empty() || g_secrets.empty())
		usage();

	io::engine engine;
	engine.spawn([&]{
		INFO() << "Starting proxy with " << g_secrets.size() << " known users";
		for (const std::string& name: addrs)
			for (io::addr addr: io::resolve(name, io::resolve_mode::PASSIVE))
				io::spawn(listener, addr).detach();
	}).detach();
	engine.run();
	return 0;
}
