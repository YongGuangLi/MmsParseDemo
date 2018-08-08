#ifndef SEMAPHOREQUEUE_H_
#define SEMAPHOREQUEUE_H_

#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <errno.h>
#include <queue>

using namespace std;

template<typename T>
class SemaphoreQueue
{
public:
	SemaphoreQueue();

	SemaphoreQueue(size_t size);

	~SemaphoreQueue();

	void set_size(size_t size);

	bool push_back(const T data, int msWait = -1);

	bool pop_front(T &data, int msWait = -1);

	int sem_wait_time( sem_t *psem, int mswait);

	inline size_t size();
private:
	pthread_mutex_t mutex_;
	queue<T> queData_;
	sem_t enques_;
	sem_t deques_;
};

template<typename T>
SemaphoreQueue<T>::SemaphoreQueue()
{
	pthread_mutex_init(&mutex_, NULL);
	sem_init( &deques_,0,0 );          //队列刚开始为空，出队信号量初始为0
}

template<typename T>
SemaphoreQueue<T>::SemaphoreQueue(size_t size)
{
	pthread_mutex_init(&mutex_, NULL);
	sem_init( &enques_,0, size );      //入队信号量初始化为size，最多可容纳size各元素
	sem_init( &deques_,0,0 );          //队列刚开始为空，出队信号量初始为0
}

template<typename T>
SemaphoreQueue<T>::~SemaphoreQueue()
{
	pthread_mutex_destroy(&mutex_);
	sem_destroy(&enques_);
	sem_destroy(&deques_);
}

template<typename T>
void SemaphoreQueue<T>::set_size(size_t size)
{
	sem_init( &enques_,0, size);         //入队信号量初始化为size，最多可容纳size各元素
}

template<typename T>
bool SemaphoreQueue<T>::push_back(const T data, int msWait)
{
	bool status = false;
	if(-1 != sem_wait_time(&enques_, msWait))
	{
		pthread_mutex_lock(&mutex_);
		queData_.push(data);
		sem_post(&deques_);
		pthread_mutex_unlock(&mutex_);
		status = true;
	}
	return status;
}

template<typename T>
bool SemaphoreQueue<T>::pop_front(T &data, int msWait)
{
	bool status = false;
	if(-1 != sem_wait_time(&deques_, msWait))
	{
		pthread_mutex_lock(&mutex_);
		data = queData_.front();
		queData_.pop();
		sem_post(&enques_ );
		pthread_mutex_unlock(&mutex_);
		status = true;
	}
	return status;
}

template<typename T>
int SemaphoreQueue<T>::sem_wait_time( sem_t *psem, int mswait)
{
	int rs = 0;
	if(mswait < 0)      //阻塞，直到 psem 大于
	{
		while((rs = sem_wait(psem)) != 0 && errno == EINTR);
	}
	else
	{
		timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);        //获取当前时间
		ts.tv_sec += (mswait / 1000 );             //加上等待时间的秒数
		ts.tv_nsec += ( mswait % 1000 ) * 1000000; //加上等待时间纳秒数

		//等待信号量，errno==EINTR屏蔽其他信号事件引起的等待中断
		while((rs = sem_timedwait( psem, &ts)) != 0 && errno == EINTR);
	}
	return rs;
}

template<typename T>
size_t SemaphoreQueue<T>::size()
{
	return queData_.size();
}
#endif
