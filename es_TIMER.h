#ifndef     __ES_TIMER_H
#define     __ES_TIMER_H

#include <stdio.h>
#include <sys/time.h>

class ES_FlashTimer{

	public:
		struct timeval start;
		
		ES_FlashTimer(){
			Start();
		}

		~ES_FlashTimer(){
		}

		unsigned long Start()
		{
			struct timeval current;
			gettimeofday(&current, NULL);
			return current.tv_sec * 1000000 + current.tv_usec;
		}

		unsigned long Elapsed(){
			struct timeval current;
			gettimeofday(&current, NULL);
			if ((current.tv_usec -= start.tv_usec) < 0){
				--current.tv_sec;
				current.tv_usec += 1000000;
			}
			current.tv_sec -= start.tv_sec;

			return current.tv_sec * 1000 + current.tv_usec / 1000;
		}

	
};

#endif
