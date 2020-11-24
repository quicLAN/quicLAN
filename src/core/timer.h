/*
    Licensed under the MIT License.
*/

typedef struct QuicLanTimer QuicLanTimer;

typedef void (*QuicLanTimerCallback)(_In_ QuicLanTimer* Timer, _In_opt_ void* Context);

struct QuicLanTimer {
    QuicLanTimerCallback TimerCallback;
    void* Context;
    std::chrono::milliseconds SleepTimeMs;
    std::mutex CancelLock;
    std::condition_variable Canceler;
    std::thread Thread;
    std::atomic_bool Canceled;
    std::atomic_bool Finished;

    QuicLanTimer(QuicLanTimerCallback Callback, void* Ctxt, uint64_t TimerMs) :
        TimerCallback(Callback), Context(Ctxt), SleepTimeMs(TimerMs), Thread(QuicLanTimerRoutine, this)
    {}

    QuicLanTimer(QuicLanTimer&) = delete;

    QuicLanTimer(QuicLanTimer&& ) = delete;

    QuicLanTimer& operator=(const QuicLanTimer&) = delete;

    ~QuicLanTimer()
    {
        // Don't clean up until the thread has finished running,
        // otherwise, a null deref may result when the timer fires.
        if (!Finished) {
            cancel();
        }
    }

    void
    cancel()
    {
        if (!Finished) {
            std::unique_lock Lock(CancelLock);
            Canceled.store(true);
            Lock.unlock();
            Canceler.notify_one();
        }
    }

private:
    static
    void QuicLanTimerRoutine(QuicLanTimer* Timer)
    {
        // Allow the OS to clean up the thread once this exits
        Timer->Thread.detach();
        std::unique_lock Lock(Timer->CancelLock);
        if (!Timer->Canceler.wait_for(Lock, Timer->SleepTimeMs, [Timer]{ return Timer->Canceled.load(); })) {
            // We only enter here when timeout has occurred and Canceled is 'false'.

            // N.B. if Lock is dropped here, and Finished set here, TimerCallback can
            // clean up Timer without deadlock or null deref.
            // Downside is that Timer could be cleaned up outside of TimerCallback while
            // TimerCallback is still running.
            Timer->TimerCallback(Timer, Timer->Context);
        }
        Timer->Finished.store(true);
    }
};