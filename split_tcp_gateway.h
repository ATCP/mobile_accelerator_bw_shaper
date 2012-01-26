#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "pcap/pcap.h"
#include <pthread.h>
#include <cstring>
#include <string.h>
#include <list>
#include <deque>
#include <assert.h>
#include <math.h>
#include <iostream>
#include <time.h>
#include "es_TIMER.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

using namespace std;

#define PKT_SIZE 1515
#define CIRCULAR_BUF_SIZE 2048
#define CIRCULAR_QUEUE_SIZE 1024

#define END_TO_END_DELAY 250000000
#define IPTOSBUFFERS 12

#define MAX_CONN_STATES	65536

#define LOCAL_WINDOW 65535
#define RECEIVE 0
#define SEND 1
#define MTU 1500
#define WIN_SCALE 5   // capacity need 1 or 0

//#define RTT_LIMIT 200000

#define MAX_RTO 500000
#define MAX_RTO_IETF 1000000

#define NUM_DUP_ACK 3
#define STD_RTT
#define LINUX_RTT

#define TIME_TO_LIVE 20000000 //us
#define DYNAMIC_RATE_FIT

//#define LOG_STAT
#define RESOLUTION 1000000
#define SLIDING_WIN_SIZE 500
#define SND_WIN_SIZE 32
#define NUM_SACK_BLOCK 1
//#define COMPLETE_SPLITTING_TCP

/* multi-user extension */
#define TOTAL_NUM_CONN 550
#define CLIENT_SACK_SIZE 5

//#define DEBUG

/* time interval estimation */
#define SLIDE_TIME_INTERVAL 1200000
#define FIX_TIME_INTERVAL_EST
#define SLIDE_TIME_DELTA 5000

typedef int BOOL;
typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned long long u_long_long;
typedef signed long long int __int64;

#define FALSE 0
#define TRUE 1

#define MY_SEQ_LT(a, b)  ((int)((a) - (b)) < 0)
#define MY_SEQ_LEQ(a, b)  ((int)((a) - (b)) <= 0)
#define MY_SEQ_GT(a, b)  ((int)((a) - (b)) > 0)
#define MY_SEQ_GEQ(a, b)  ((int)((a) - (b)) >= 0)

ES_FlashTimer timer;
FILE* test_file;

u_int APP_PORT_NUM;
u_int APP_PORT_FORWARD;
u_int MAX_SEND_RATE;
u_int MIN_SEND_RATE;
u_int INITIAL_RATE;
u_int SND_BEYOND_WIN;
u_int NUM_PKT_BEYOND_WIN;
u_int RTT_LIMIT;
u_int BDP;


enum DIRECTION
{
	SERVER_TO_CLIENT,
	CLIENT_TO_SERVER,
};
struct seg_info
{
	u_long_long forward_time;
	u_int seq_num;
	u_int data_len;
};
struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};
struct psd_header
{
	ip_address saddr;
	ip_address daddr;
	u_char mbz;
	u_char ptoto;
	u_short tcp_len;
};
struct mac_header
{
	u_char mac_src[6];		// mac source address
	u_char mac_dst[6];		// mac destination address
	u_short opt;
};
struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service
	u_short tlen;			// Total length
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
};
struct tcp_header
{
	u_short sport;		     //   Source   port
	u_short dport;		     //   Destination   port
	u_int seq_num;		     //   sequence   number
	u_int ack_num;		     //   acknowledgement   number
	u_short hdr_len_resv_code; //   Datagram   length
	u_short window;			 //   window
	u_short crc;			 //   Checksum
	u_short urg_pointer;     //   urgent   pointer
};
struct tcp_sack_block
{
	u_int left_edge_block;
	u_int right_edge_block;
};

struct tcp_sack
{
	u_char pad_1;
	u_char pad_2;
	u_char kind;
	u_char length;
	tcp_sack_block sack_block[CLIENT_SACK_SIZE];

};
struct sack_header
{
	tcp_sack_block sack_list[CLIENT_SACK_SIZE];
	u_int _size;

	sack_header()
	{
		for (u_short i = 0; i < CLIENT_SACK_SIZE; i ++)
		{
			sack_list[i].left_edge_block = 0;
			sack_list[i].right_edge_block= 0;
		}
		_size = 0;
	}

	void inline flush()
	{
		for (u_short i = 0; i < CLIENT_SACK_SIZE; i ++)
		{
			sack_list[i].left_edge_block = 0;
			sack_list[i].right_edge_block = 0;
		}
		_size = 0;
	}

	u_int size()
	{
		return _size;
	}

};

struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
};
struct ForwardPkt
{
	void *data;
	struct pcap_pkthdr header;
	u_char pkt_data[PKT_SIZE];
	struct ForwardPkt* next;
	struct ForwardPkt* prev;

	u_int seq_num;
	u_short data_len;
	u_short ctr_flag;
	u_long_long snd_time;
	u_long_long rtx_time;
	u_int num_dup;
	u_long_long rcv_time;
	u_short sPort, dPort;
	u_int index;
	bool occupy;
	u_int tcb;
	bool is_rtx;

	void initPkt()
	{
            seq_num = 0;
            data_len = 0;
            ctr_flag = 0;
            snd_time = 0;
            rtx_time = 0;
            rcv_time = 0;
            num_dup = 0;
            sPort = 0;
            dPort = 0;
            occupy = false;
            is_rtx = true;
            index = 0;
	}
	void PktHandler()
	{
		struct tm *ltime;
		char timestr[16];
		time_t local_tv_sec;
		mac_header* mh;
		ip_header* ih;
		tcp_header* th;
		udp_header* uh;
		u_int ip_len;
		u_int tcp_len;
		u_int data_len;
		u_int seq_num, ack_num;
		u_short sport, dport;
		u_short ctr_flag;

		local_tv_sec = header.ts.tv_sec;
		ltime=localtime(&local_tv_sec);
		strftime( timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("%s,%.6d len:%d ", timestr, header.ts.tv_usec, header.len);
		mh = (mac_header *) pkt_data;
		printf("%d:%d:%d:%d:%d:%d -> %d:%d:%d:%d:%d:%d ", mh->mac_dst[0],
		mh->mac_dst[1], mh->mac_dst[2], mh->mac_dst[3], mh->mac_dst[4],
		mh->mac_dst[5], mh->mac_src[0], mh->mac_src[1], mh->mac_src[2],
		mh->mac_src[3], mh->mac_src[4], mh->mac_src[5]);
		if (pkt_data[14] != '\0')
		{
                    ih = (ip_header *) (pkt_data + 14); //length of ethernet header
                    ip_len = (ih->ver_ihl & 0xf) * 4;
                    printf("%d.%d.%d.%d -> %d.%d.%d.%d %d ",  ih->saddr.byte1,  ih->saddr.byte2,  ih->saddr.byte3, ih->saddr.byte4, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, ih->proto);

                    if ((int)ih->proto == 17) //UDP
                    {
                            printf("UDP ");
                            uh = (udp_header *)((u_char *)ih + ip_len);
                            sport = ntohs(uh->sport);
                            dport = ntohs(uh->dport);
                            printf("%hu -> %hu\n", sport, dport);
                            return;
                    }
                    else if ((int)ih->proto == 6) //TCP
                    {
                            printf("TCP ");
                            th = (tcp_header *)((u_char *)ih + ip_len);
                            sport = ntohs(th->sport);
                            dport = ntohs(th->dport);
                            seq_num = ntohl(th->seq_num);
                            ack_num = ntohl(th->ack_num);
                            tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
                            ctr_flag = ntohs(th->hdr_len_resv_code)&0x003f;
                            if (header.len > 60)
                                    data_len = header.len - 14 - ip_len - tcp_len;
                            else
                                    data_len = 0;
                            printf("%hu ", ntohs(th->hdr_len_resv_code)&0x003f);
                            printf("%hu -> %hu %u %u %u\n", sport, dport, seq_num, ack_num, data_len);
                            return;
                    }
		}

		printf("\n");
		return;
	}
};
struct node
{
		int data;
		node *link;
};
class linklist
{
public:

	node *p;

	linklist()
	{
		p=NULL;
	}

	void append(int num)
	{
		node *q,*t;

		if( p == NULL )
		{
			p = new node;
			p->data = num;
			p->link = NULL;
		}
		else
		{
			q = p;
			while( q->link != NULL )
				q = q->link;

			t = new node;
			t->data = num;
			t->link = NULL;
			q->link = t;
		}
	}
	void add_as_first( int num )
	{
		node *q;

		q = new node;
		q->data = num;
		q->link = p;
		p = q;
	}
	void addafter( int c, int num )
	{
		node *q,*t;
		int i;
		for(i=0,q=p;i<c;i++)
		{
			q = q->link;
			if(q == NULL )
			{
				printf("There are less than %d elements\n", c);
				return;
			}
		}

		t = new node;
		t->data = num;
		t->link = q->link;
		q->link = t;
	}
	void del(int num)
	{
		node *q,*r;
		q = p;
		if( q->data == num )
		{
			 p = q->link;
			 delete q;
			 return;
		}

		r = q;
		while( q!=NULL )
		{
			if( q->data == num )
			{
				r->link = q->link;
				delete q;
				return;
			}

			r = q;
			q = q->link;
		}
		printf("Element %d not Found\n", num);
	}

	void display()
	{
		node *q;
		for(q = p ; q != NULL ; q = q->link)
			printf("%d\n", q->data);
	}

	int count()
	{
		node *q;
		int c=0;
		for( q=p ; q != NULL ; q = q->link )
			c++;

		return c;
	}

	~linklist()
	{
		node *q;
		if( p == NULL )
			return;

		while( p != NULL )
		{
			q = p->link;
			delete p;
			p = q;
		}
	}
};
struct state_array
{
	u_int state_id[TOTAL_NUM_CONN];
	u_int num;
	u_int it;

	state_array()
	{
		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			state_id[i] = 0;
		}

		num = 0;
		it = 0;
	}

	BOOL isEmpty()
	{
		if (!num)
			return TRUE;
		else
			return FALSE;
	}

	void flush()
	{
		num = it = 0;
		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			state_id[i] = 0;
		}
	}

	u_int iterator()
	{
		return it;
	}

	void next()
	{
		if (num)
			it = (it + 1) % num;
	}

	u_int size()
	{
		return num;
	}

	BOOL find(u_int port)
	{
		for (u_int i = 0; i < num; i ++)
		{
			if (state_id[i] == port)
				return TRUE;
		}

		return FALSE;
	}

	void add(u_int port)
	{
		state_id[num] = port;
		num ++;
	}

	void del(u_int index)
	{
		for (u_int i = index; i < num - 1; i ++)
			state_id[i] = state_id[i + 1];
		state_id[num - 1] = 0;
		num --;
		if (num)
			it = index % num;
		else
			it = 0;

	}

	void deleteByValue(u_int port)
	{
		u_int index;
		for (u_int i = 0; i < num; i ++)
		{
			if (state_id[i] == port)
			{
				index = i;
				break;
			}
		}

		del(index);
	}
};
struct ForwardPktBuffer
{
	ForwardPkt* pktQueue;

	u_int capacity, _size, _head, _tail, _unAck, _pkts, _last_head, _last_pkts;

	ForwardPktBuffer(u_int size):capacity(size)
	{
		pktQueue = (ForwardPkt *)malloc(sizeof(ForwardPkt)*capacity);
		for (int i = 0; i < capacity; i ++)
			pktQueue[i].initPkt();

		_head = _tail = _size = _unAck = _pkts = _last_head = _last_pkts = 0;
	}

	void inline flush()
	{
		init();
	}

	~ForwardPktBuffer()
	{
		free(pktQueue);
	}

	inline void init()
	{
		for (int i = 0; i < capacity; i ++)
			pktQueue[i].initPkt();

		_head = _tail = _size = _unAck = _pkts = _last_head = _last_pkts = 0;
	}

	inline ForwardPkt* unAck() { return pktQueue + (_unAck % capacity); }
	inline void unAckNext() { _unAck = (_unAck + 1) % capacity; }
	inline ForwardPkt* head() { return pktQueue + (_head % capacity); }
	inline void headNext() { _head = (_head + 1) % capacity; _pkts --; }
	inline void headPrev()
	{
            if (_head == 0)
                _head = capacity - 1;
            else
                _head = (_head - 1) % capacity;

            _pkts ++;
	}
	inline void lastHeadNext() { _last_head = (_last_head + 1) % capacity; _last_pkts --; }
	inline void lastHeadPrev()
	{
            if (_last_head == 0)
                _last_head = capacity - 1;
            else
                _last_head = (_last_head - 1) % capacity;

            _last_pkts ++;

	}
        inline ForwardPkt* lastHead() { return pktQueue + (_last_head % capacity); }
	inline ForwardPkt* tail() { return pktQueue + (_tail % capacity); }
	inline void tailNext() { _tail = (_tail + 1) % capacity; _pkts ++; }

	inline ForwardPkt* pkt(u_int _index) { return pktQueue + (_index % capacity); }
	inline u_int pktNext(u_int _index) { return _index = (_index + 1) % capacity; }

	inline u_int size() { return _size; }
	inline u_int pkts() { return _pkts; }

	inline void increase() { _size ++; }
	inline void decrease() { _size --; }
};
struct Packet
{
	u_int seqNo;
	u_long_long time;
	u_int len;

	Packet()
	{
		len = seqNo = time = 0;
	}

	void flush()
	{
		len = seqNo = time = 0;
	}
};
struct SlideWindow
{
	Packet* window;
	u_int _size, _bytes, capacity, delta, interval;
	u_long_long sample_time;

	SlideWindow(u_int size, u_int _interval, u_int _delta)
	{
		capacity = size;
		delta = _delta;
		interval = _interval;
		window = (Packet *)malloc(sizeof(Packet) * size);
		_size = _bytes = sample_time = 0;
	}

	~SlideWindow()
	{
		free(window);
	}

	u_int size()
	{
	  return _size;
	}

	u_int bytes()
	{
	  return _bytes;
	}

	BOOL isEmpty()
	{
          if (_size == 0)
             return TRUE;
          else
             return FALSE;
	}

	u_int bytesCount()
	{
          if (isEmpty())
          {
             return 0;
          }
          else
             return window[_size-1].seqNo - window[0].seqNo;
	}

	u_long_long frontTime()
	{
	  return window[0].time;
	}

	u_long_long tailTime()
	{
	  if (isEmpty())
            return 0;
	  else
            return window[_size-1].time;
	}

        u_long_long estmateInterval(u_long_long current_time)
	{
		if (!sample_time)
		    return 0;
		else
		    return current_time - sample_time;
	}

	u_long_long nextEstmateSampleTime(u_long_long current_time)
	{
		if (!sample_time)
		{
		    sample_time = current_time;
		    return sample_time;
		}
		else
		{
		    sample_time += delta;
		    return sample_time;
		}
	}

	void another_shift()
	{
		while (frontTime() < sample_time && _bytes > 0 && _size >= 2)
		{
			shift();
			_size --;
		}

	}
	u_long_long timeInterval(u_long_long current_time)
	{
		if (isEmpty())
			return 0;
		else
			return current_time - window[0].time;
	}

	void shift()
	{
		_bytes -= window[0].len;
		for (u_int i = 0; i < _size - 1; i ++)
		{
			window[i].len = window[i+1].len;
			window[i].time = window[i+1].time;
			window[i].seqNo = window[i+1].seqNo;
		}
	}

	void put(u_int len, u_long_long time, u_int seqNo)
	{
		if (_size < capacity)
		{
			window[_size].len = len;
			window[_size].time = time;
			window[_size].seqNo = seqNo;
			_bytes += window[_size].len;
			_size ++;
		}
		else
		{
			assert(_size == capacity);

			shift();
			window[_size-1].len = len;
			window[_size-1].time = time;
			window[_size-1].seqNo = seqNo;
			_bytes += window[_size-1].len;
		}
	}

	void another_put(u_int len, u_long_long time, u_int seqNo)
	{

		if (_size < capacity)
		{
			window[_size].len = len;
			window[_size].time = time;
			window[_size].seqNo = seqNo;
			_bytes += window[_size].len;
			_size ++;
		}
		else
		{
			assert(_size == capacity);

			shift();
			window[_size-1].len = len;
			window[_size-1].time = time;
			window[_size-1].seqNo = seqNo;
			_bytes += window[_size-1].len;
		}
	}

	void flush()
	{
		_size = _bytes = sample_time = 0;
		for (u_int i = 0; i < capacity; i ++)
			window[i].flush();
	}

};
struct Forward
{
	pcap_t *dev;
	u_int delay;
	DIRECTION mode;

	ForwardPktBuffer pktQueue;
	pthread_mutex_t mutex;

	pthread_cond_t m_eventElementAvailable;
	pthread_cond_t m_eventSpaceAvailable;

	Forward(pcap_t *_dev, u_int count, u_int _delay, DIRECTION _mode) : dev(_dev), delay(_delay), mode(_mode), pktQueue(count)
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventSpaceAvailable, NULL );
		pthread_cond_init(&m_eventElementAvailable, NULL);

	}

	~Forward()
	{
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&m_eventElementAvailable);
		pthread_cond_destroy(&m_eventSpaceAvailable);
	}
};
struct DATA
{
	pcap_t *dev_this;
	pcap_t *dev_another;
	char *name_this;
	char *name_another;
	DIRECTION mode;
	Forward *forward, *forward_back;
	DATA(pcap_t *dev_0, pcap_t *dev_1, char *name_0, char *name_1, DIRECTION _mode, Forward *_forward, Forward *_forward_back) : dev_this(dev_0), dev_another(dev_1), name_this(name_0), name_another(name_1), mode(_mode), forward(_forward), forward_back(_forward_back){}

};

/*u_char console_y;

u_char getCursorX(void)
{
CONSOLE_SCREEN_BUFFER_INFO csbInfo;
GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbInfo);
return csbInfo.dwCursorPosition.X;
}
u_char getCursorY(void)
{
CONSOLE_SCREEN_BUFFER_INFO csbInfo;
GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbInfo);
return csbInfo.dwCursorPosition.Y;
}

int gotoTextPos(u_char x, u_char y)
{
	COORD cd;
	cd.X = x;
	cd.Y = y;
	return SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), cd);
}
*/
