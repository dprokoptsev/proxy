/**
 * mutex.h -- syncio based mutex
 *
 * This file is part of mongoz, a more sound implementation
 * of mongodb sharding server.
 *
 * Copyright (c) 2016 YANDEX LLC
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

#pragma once

#include "wait.h"
#include "scheduler.h"
#include <mutex>
#include <atomic>

namespace io { namespace impl {

class Mutex {
public:
    Mutex(): held_(0) {}

    void lock()
    {
        WaitQueue::Lock lock(queue_);
        Scheduler* s = Scheduler::current();
        Coroutine* c = s->currentCoroutine();
        for (Coroutine* z = 0; !held_.compare_exchange_strong(z, c); z = 0)
            s->stepDownCurrent(&queue_, timeout());
    }
    
    void unlock()
    {
        held_ = 0;
        queue_.scheduleOne();
    }
    
private:
    std::atomic<Coroutine*> held_;
    WaitQueue queue_;
};

}} // namespace io::impl
