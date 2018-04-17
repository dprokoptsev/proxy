ACLOCAL_AMFLAGS = -I m4

sbin_PROGRAMS = proxy

proxy_SOURCES = \
    src/main.cpp \
    \
    contrib/syncio/src/ctx.cpp \
    contrib/syncio/src/stream.cpp \
    contrib/syncio/src/unwind-cxxabi.cpp \
    contrib/syncio/src/task.cpp \
    contrib/syncio/src/log.cpp \
    contrib/syncio/src/tls.cpp \
    contrib/syncio/src/engine.cpp \
    contrib/syncio/src/wait.cpp \
    contrib/syncio/src/sched.cpp \
    contrib/syncio/src/addr.cpp \
    contrib/syncio/src/mutex.cpp \
    contrib/syncio/src/fd.cpp \
    contrib/syncio/src/poller.cpp \
    contrib/syncio/src/ctx_x86_64.s


dist_noinst_HEADERS = \
    \
    contrib/syncio/src/scheduler.h \
    contrib/syncio/src/valgrind.h \
    contrib/syncio/src/poller.h \
    contrib/syncio/src/tls.h \
    contrib/syncio/src/wait.h \
    contrib/syncio/src/mutex.h \
    contrib/syncio/src/helper.h \
    contrib/syncio/src/debug.h \
    contrib/syncio/src/log.h \
    contrib/syncio/src/ctx.h \
    \
    contrib/syncio/include/syncio/addr.h \
    contrib/syncio/include/syncio/impl/bind.h \
    contrib/syncio/include/syncio/impl/future.h \
    contrib/syncio/include/syncio/impl/utility.h \
    contrib/syncio/include/syncio/time.h \
    contrib/syncio/include/syncio/fd.h \
    contrib/syncio/include/syncio/id.h \
    contrib/syncio/include/syncio/syncio.h \
    contrib/syncio/include/syncio/mutex.h \
    contrib/syncio/include/syncio/algorithm.h \
    contrib/syncio/include/syncio/stream.h \
    contrib/syncio/include/syncio/debug.h \
    contrib/syncio/include/syncio/error.h \
    contrib/syncio/include/syncio/engine.h \
    contrib/syncio/include/syncio/task.h

proxy_CXXFLAGS = -I$(srcdir)/contrib/syncio/include -std=c++0x
proxy_LDFLAGS = -lpthread -lcrypto

if DEBUG
proxy_CXXFLAGS += -DIO_DEBUG -DIO_DEBUG_CIRCULAR
endif

if CPUPROFILE
proxy_CXXFLAGS += -DCPUPROFILE
proxy_LDFLAGS += -lprofiler
endif

