#include "split_tcp_gateway.h"

enum STATE
{
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_REVD,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK,
};
enum PHASE
{
	NORMAL,
	FAST_RTX,
	PAUSE,
	NORMAL_TIMEOUT,
};

struct SendDataPktQueue
{
	ForwardPkt* head;
	ForwardPkt* tail;
	u_int size;

	SendDataPktQueue()
	{
		head = tail = NULL;
		size = 0;
	}

	~SendDataPktQueue()
	{
		struct ForwardPkt* h = NULL;
		struct ForwardPkt* p = NULL;

		while(head)
		{
			h = head;
			p = h->next;
			head = h;
			if (head == NULL)
				tail = head;
			else
				head->prev = NULL;
			free(h);
		}

	}

	u_int num()
	{
		return size;
	}

	bool IsEmpty()
	{
		if (head == NULL && tail == NULL)
			return true;
		else
			return false;
	}

	ForwardPkt* FetchPkt(u_int seq_want)
	{
		struct ForwardPkt* p;

		for (p = head; p; p = p->next)
		{
			if (p->seq_num == seq_want)
				return p;
		}
		return NULL;
	}

	bool Dequeue(u_int ack_up)
	{
		struct ForwardPkt* h;
		struct ForwardPkt* p;

		if (head == NULL && tail == NULL)
		{
			printf("Queue is empty\n");
			return true;
		}

		while(ack_up > head->seq_num)
		{
			h = head;
			p = h->next;
			head = p;
			if (head == NULL)
			{
				tail = head;
				free(h);
				size --;
				return false;
			}
			else
				head->prev = NULL;
			free(h);
			size --;
		}
		return false;
	}

	void EnqueueAndSort(u_int seq_num, u_short data_len, u_short flag, DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data)
	{
		ForwardPkt* pkt = (ForwardPkt *)malloc(sizeof(ForwardPkt));
		pkt->seq_num = seq_num;
		pkt->data_len = data_len;
		pkt->ctr_flag = flag;
		pkt->next = NULL;
		pkt->prev = NULL;
		pkt->num_dup = 0;
		pkt->data = (void *)data;
		memcpy(&pkt->header,  header, sizeof(struct pcap_pkthdr));
		memcpy(pkt->pkt_data, pkt_data, header->len);
		size ++;
		//printf("Enqueue packet seq_num: %u\n", pkt->seq_num);

		if (head == NULL && tail == NULL)
		{
			head = tail = pkt;
			return;
		}

		if (pkt->seq_num > tail->seq_num)
		{
			tail->next = pkt;
			pkt->prev = tail;
			tail = pkt;
		}
		else
		{
			struct ForwardPkt* p = NULL;
			for (p = tail; p; p = p->prev)
			{
				if (pkt->seq_num > p->seq_num)
				{
					pkt->next = p->next;
					pkt->prev = p;
					p->next->prev = pkt;
					p->next = pkt;
					return;
				}
				else if (pkt->seq_num == p->seq_num)
				{
					//printf("Duplicate pkt\n");
					pkt->num_dup ++;
					return;
				}
				else
					continue;
			}
			pkt->next = head;
			head->prev = pkt;
			head = pkt;
		}
	}


};
struct serverState
{
	u_short send_data_id;				// previous sent data identity

	STATE state;						// connection state
	PHASE phase;

	/* send sequence variables */
	u_int snd_wnd;						// advertised by receiver to gateway server
	u_int snd_nxt;						// send next
	u_int snd_una;						// send unacknowledged
	u_int snd_max;						// highest sequence number sent
 	u_int seq_nxt;

	u_short win_limit;
	BOOL ignore_adv_win;
	u_short win_scale;

	BOOL SACK_permitted;

	serverState()
	{
		win_limit = 0; // set Adv win limit to be 0
		ignore_adv_win = FALSE;
		SACK_permitted = FALSE;

		phase = NORMAL;
		state = LISTEN;
		win_scale = 0;
		snd_wnd = snd_nxt = snd_una = snd_max = seq_nxt = 0;
	}

	void flush()
	{
		snd_wnd = snd_nxt = snd_una = snd_max = seq_nxt = 0;
		win_limit = 0;
		ignore_adv_win = FALSE;
		SACK_permitted = FALSE;
		win_scale = 0;
		state = LISTEN;
		phase = NORMAL;
	}
};
struct clientState
{
	u_short send_data_id;				// previous sent data identity

	STATE state;						// connection state

	/* receive sequence variables */
	u_int rcv_wnd;						// advertised by the gateway client to sender
	u_int rcv_nxt;						// receive next
	u_int rcv_adv;						// advertised window by other end
	u_int snd_nxt;
	u_int seq_nxt;
	u_short win_scale;
	u_short sender_win_scale;
	ForwardPkt *httpRequest;			// http request packet
	u_short ack_count;

	sack_header sack;

	clientState()
	{
		httpRequest = new ForwardPkt();
		httpRequest->initPkt();

		win_scale = sender_win_scale = 0;
		ack_count = 0;
		send_data_id = rcv_wnd = rcv_nxt = rcv_adv =  snd_nxt = seq_nxt = 0;
	}

	void flush()
	{
		send_data_id = rcv_wnd = rcv_nxt = rcv_adv =  snd_nxt = seq_nxt = 0;
		httpRequest->initPkt();
		win_scale = sender_win_scale = 0;
		ack_count = 0;
		state = LISTEN;
		sack.flush();

	}

	~clientState()
	{
		delete httpRequest;
	}
};

struct TCB;
struct conn_state
{
	u_long_long initial_time;

	u_char client_mac_address[6];
	u_char server_mac_address[6];

	ip_address client_ip_address;
	ip_address server_ip_address;

	u_short cPort;
	u_short sPort;

	ForwardPktBuffer dataPktBuffer;

	pthread_mutex_t mutex;
	pthread_cond_t m_eventElementAvailable;
	pthread_cond_t m_eventSpaceAvailable;
	serverState server_state;
	clientState client_state;

	// For Experiment Output
	FILE* rttFd;

	u_int send_rate;
	u_int RTT;
	u_int LAST_RTT;
	u_int RTT_limit;
	u_int mdev;
	u_int nxt_timed_seqno;

	u_long_long last_ack_rcv_time;
	u_int last_ack_seqno;
	u_long_long cur_ack_rcv_time;
	u_int cur_ack_seqno;

	u_int cumul_ack;
	u_int accounted_for;
	u_int rcv_thrughput_approx;
	u_int rcv_thrughput;
	u_int ack_interarrival_time;
	u_int dft_cumul_ack;

	u_int rto;
	u_int rtt_std_dev;

	tcp_sack_block sack_block[NUM_SACK_BLOCK];
	u_short sack_block_num;
	u_int sack_diff;
	u_int undup_sack_diff;
	u_short sack_target_block;
	u_int max_sack_edge;
	u_int rcv_max_seq_edge;

	u_long_long ref_ack_time;
	u_int ref_ack_seq_no;

	u_short MSS;
	u_int zero_window_seq_no;
	SlideWindow sliding_avg_win;

	u_int FRTO_ack_count;
	u_int FRTO_dup_ack_count;
    BOOL send_out_awin; //use in fast retransmit
	u_int max_data_len;

#ifdef STD_RTT

	u_int RTT_IETF;
	u_int rtt_std_dev_ietf;
	u_int rto_ietf;
	u_int nxt_timed_seqno_ietf;

#endif

	TCB *_tcb;

	conn_state(u_int count): dataPktBuffer(count), sliding_avg_win (SLIDING_WIN_SIZE, 0, 0)
	{
		init_state();
	}

	conn_state(u_char client_mac[], u_char server_mac[], ip_address client_ip, ip_address server_ip, u_short client_port, u_short server_port, u_int count) : client_ip_address(client_ip), server_ip_address(server_ip), cPort(client_port), sPort(server_port), dataPktBuffer(count), sliding_avg_win (SLIDING_WIN_SIZE, 0, 0)
	{
		client_ip_address = client_ip;
		server_ip_address = server_ip;
		cPort = client_port;
		sPort = server_port;

		initial_time = timer.Start();

		memcpy(client_mac_address, client_mac, 6);
		memcpy(server_mac_address, server_mac, 6);
	        init_state();
	}

	void inline init_state()
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventSpaceAvailable, NULL );
		pthread_cond_init(&m_eventElementAvailable, NULL);
		rttFd = NULL;

		_tcb = NULL;

		initial_time = 0;
		RTT = 0; //us
		LAST_RTT = 0; //us
		RTT_limit = RTT_LIMIT; //us
		rtt_std_dev = 0;

		mdev = 0;
		last_ack_rcv_time = last_ack_seqno = cur_ack_rcv_time = cur_ack_seqno = cumul_ack = accounted_for = rcv_thrughput_approx = rcv_thrughput = 0;

		ack_interarrival_time = dft_cumul_ack = 0;
		rto = MAX_RTO; //us

		sack_block_num = 0;
		sack_target_block = 0;
		rcv_max_seq_edge = 0;
		sack_diff = 0;
		max_sack_edge = 0;

		undup_sack_diff = 0;
		for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
		{
			sack_block[i].left_edge_block = sack_block[i].right_edge_block = 0;
		}

		ref_ack_time = 0;
		ref_ack_seq_no = 0;
		send_out_awin = FALSE;

		MSS = 1460; //wired network
		//nxt_ack_seqno = 0;
		nxt_timed_seqno = 0;
		zero_window_seq_no = 0;
		max_data_len = 0;

#ifdef STD_RTT

		RTT_IETF = 0;
		rtt_std_dev_ietf = 0;
		rto_ietf = MAX_RTO_IETF;
		nxt_timed_seqno_ietf = 0;

#endif
		FRTO_ack_count = FRTO_dup_ack_count = 0;

		ref_ack_time = 0;
		ref_ack_seq_no = 0;
		//reset_timer = FALSE;
	}

	void inline init_state_ex(u_char client_mac[], u_char server_mac[], ip_address client_ip, ip_address server_ip, u_short client_port, u_short server_port, TCB *tcb)
	{
		client_ip_address = client_ip;
		server_ip_address = server_ip;
		cPort = client_port;
		sPort = server_port;

		initial_time = timer.Start();

		_tcb = tcb;

		memcpy(client_mac_address, client_mac, 6);
		memcpy(server_mac_address, server_mac, 6);
	}

	void inline flush()
	{
		if (rttFd)
		{
			fclose(rttFd);
			rttFd = NULL;
		}

		sliding_avg_win.flush();
		client_state.flush();
		server_state.flush();
		dataPktBuffer.flush();

		_tcb = NULL;

		initial_time = 0;
		RTT = 0; //ms
		LAST_RTT = 0; //ms
		RTT_limit = RTT_LIMIT; //ms
		rtt_std_dev = 0;

		mdev = 0;
		last_ack_rcv_time = last_ack_seqno = cur_ack_rcv_time = cur_ack_seqno = cumul_ack = accounted_for = rcv_thrughput_approx = rcv_thrughput = 0;

		ack_interarrival_time = dft_cumul_ack = 0;
		rto = MAX_RTO; //ms

		sack_block_num = 0;
		sack_target_block = 0;
		rcv_max_seq_edge = 0;
		sack_diff = 0;
		max_sack_edge = 0;

		undup_sack_diff = 0;
		for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
		{
			sack_block[i].left_edge_block = sack_block[i].right_edge_block = 0;
		}

		ref_ack_time = 0;
		ref_ack_seq_no = 0;
		send_out_awin = FALSE;

		MSS = 1460; //wired network
		//nxt_ack_seqno = 0;
		nxt_timed_seqno = 0;
		zero_window_seq_no = 0;
		max_data_len = 0;

#ifdef STD_RTT

		RTT_IETF = 0;
		rtt_std_dev_ietf = 0;
		rto_ietf = MAX_RTO_IETF;
		nxt_timed_seqno_ietf = 0;

#endif
		FRTO_ack_count = FRTO_dup_ack_count = 0;

		ref_ack_time = last_ack_rcv_time = cur_ack_rcv_time;
		ref_ack_seq_no = last_ack_seqno = cur_ack_seqno;
		//reset_timer = FALSE;

		initial_time = 0;
	}

	~conn_state()
	{
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&m_eventElementAvailable);
		pthread_cond_destroy(&m_eventSpaceAvailable);
	}
};

struct TCB
{
	conn_state* conn[MAX_CONN_STATES + 1];

	u_int send_rate;
	u_int send_rate_lower;
	u_int send_rate_upper;
	u_int aggre_bw_estimate;
	u_int send_beyong_win;
	u_int sample_rate;

	pthread_cond_t m_eventConnStateAvailable;
	pthread_mutex_t mutex;
	state_array states;
	SlideWindow sliding_avg_window;
	SlideWindow sliding_snd_window;
	u_int rcv_thrughput;
	u_int rcv_thrughput_approx;

	u_long_long initial_time;

	ip_address client_ip_address;
	ip_address server_ip_address;

	u_int totalByteSent;

	u_int RTT;
	u_int RTT_limit;
	u_long_long startTime;
	u_int pkts_transit;

	TCB():sliding_avg_window (SLIDING_WIN_SIZE, SLIDE_TIME_INTERVAL, SLIDE_TIME_DELTA), sliding_snd_window (SND_WIN_SIZE, 0, 0)
	{
		send_rate = INITIAL_RATE; //Bps
		send_rate_lower = MIN_SEND_RATE; //Bps
		send_rate_upper = MAX_SEND_RATE; //- 50000; //Bps
		send_beyong_win = SND_BEYOND_WIN; // send beyong the advertising window

		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventConnStateAvailable, NULL );
		for (int i = 0; i < MAX_CONN_STATES + 1; i ++)
		{
			conn[i] = NULL;
		}

		rcv_thrughput = rcv_thrughput_approx = sample_rate = initial_time = pkts_transit = 0;

		totalByteSent = RTT = 0;

		RTT_limit = RTT_LIMIT;
		startTime = timer.Start();

	}

	void init_tcb(ip_address client_ip, ip_address server_ip)
	{
		initial_time = startTime = timer.Start();
		//sliding_avg_window.sample_time = initial_time;

		client_ip_address = client_ip;
		server_ip_address = server_ip;

	}

	void flush()
	{
		send_rate = INITIAL_RATE; //Bps
		send_rate_lower = MIN_SEND_RATE; //Bps
		send_rate_upper = MAX_SEND_RATE; //- 50000; //Bps
		send_beyong_win = SND_BEYOND_WIN; // send beyong the advertising window

		for (int i = 0; i < MAX_CONN_STATES + 1; i ++)
		{
			conn[i] = NULL;
		}

		rcv_thrughput = rcv_thrughput_approx = sample_rate = initial_time = pkts_transit = 0;
		states.flush();
		sliding_avg_window.flush();
		//snd_window.flush();

		totalByteSent = RTT = 0;
		RTT_limit = RTT_LIMIT;
		startTime = timer.Start();
		initial_time = 0;
	}

	void add_conn(u_short sport, conn_state *new_conn)
	{
		conn[sport] = new_conn;
		states.add(sport);
	    pthread_cond_signal(&m_eventConnStateAvailable);
	}

	~TCB()
	{
		pthread_cond_destroy(&m_eventConnStateAvailable);
		pthread_mutex_destroy(&mutex);
		for (int i = 0; i < MAX_CONN_STATES + 1; i ++)
		{
			if (conn[i] != NULL)
				conn[i] = NULL;
		}

	}
};

conn_state *conn_table[TOTAL_NUM_CONN];
TCB *tcb_table[TOTAL_NUM_CONN];

struct mem_pool
{
	state_array ex_tcb;
	//state_array ex_conn;
	pthread_cond_t m_eventConnStateAvailable;
	pthread_mutex_t mutex;

	u_int _size;

	mem_pool()
	{
		printf("MOBILE ACCELERATOR INITIALIZES THE CONNECTION TABLES\n");
		if ((test_file = fopen("parameters.txt", "r")) == NULL)
		{
			printf("file parameters.txt is missing or corrupted\n");
			exit(-1);
		}

		fscanf(test_file, "%u\n", &APP_PORT_NUM);
		fscanf(test_file, "%u\n", &APP_PORT_FORWARD);
		fscanf(test_file, "%u\n", &MAX_SEND_RATE);
		fscanf(test_file, "%u\n", &INITIAL_RATE);
		fscanf(test_file, "%u\n", &MIN_SEND_RATE);
		fscanf(test_file, "%u\n", &SND_BEYOND_WIN);
		fscanf(test_file, "%u\n", &NUM_PKT_BEYOND_WIN);
		fscanf(test_file, "%u\n", &BDP); // num of
		fscanf(test_file, "%u\n", &RTT_LIMIT); //us

		init_mem_pool();
	}

	void init_mem_pool()
	{
		pthread_mutex_init(&mutex, NULL);
		pthread_cond_init(&m_eventConnStateAvailable, NULL );

		_size = 0;

		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			conn_table[i] = new conn_state(CIRCULAR_BUF_SIZE);
		}

		printf("CONN MEMORY ALLOCATED\n");

		for (u_int i = 0; i < TOTAL_NUM_CONN; i ++)
		{
			tcb_table[i] = new TCB;
		}

		printf("TCB MEMORY ALLOCATED");

	}

	void inline add_tcb(u_int value)
	{
		ex_tcb.add(value);
	    pthread_cond_signal(&m_eventConnStateAvailable);
	}

	void inline flush()
	{
		ex_tcb.flush();
		_size = 0;
	}

	~mem_pool()
	{
		pthread_mutex_destroy(&mutex);
		pthread_cond_destroy(&m_eventConnStateAvailable);
		delete[] conn_table;
		delete[] tcb_table;
	}

}pool;

struct RateCtrlParam
{
	Forward* forward_it;
	u_int id;
};

u_int HashBernstein(const char *key, size_t len)
{
	u_int hash = 5381;
	for(u_int i = 0; i < len; ++i)
		hash = 33 * hash + key[i];
	return (hash ^ (hash >> 16)) % TOTAL_NUM_CONN;
}

struct conn_Htable
{
	u_int size;

	conn_Htable()
	{
		size = 0;
	}

	int Hash(const char *key, size_t len)
	{
		u_int i = HashBernstein(key, len);

		if (size == TOTAL_NUM_CONN)
			return -1;

		while(conn_table[i]->initial_time)
		{
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		size ++;

		return i;
	}

	int search(const char *key, size_t len, u_short cPort)
	{
		u_int i = HashBernstein(key, len);
		while (conn_table[i]->initial_time)
		{
			if (conn_table[i]->cPort == cPort)
				return i;
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		return -1;
	}
}conn_hash;
struct tcb_Htable
{
	u_int size;

	tcb_Htable()
	{
		size = 0;
	}

	int Hash(const char *key, size_t len)
	{
		u_int i = HashBernstein(key, len);

		if (size == TOTAL_NUM_CONN)
			return -1;

		while(tcb_table[i]->initial_time)
		{
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		size ++;

		return i;
	}

	int search(const char *key, size_t len, ip_address *client_ip)
	{
		u_int i = HashBernstein(key, len);
		while (tcb_table[i]->initial_time)
		{
			if (memcmp(&tcb_table[i]->client_ip_address, client_ip, sizeof(ip_address)) == 0)
				return i;
			i = (i + 1) % TOTAL_NUM_CONN;
		}

		return -1;
	}
}tcb_hash;

char *iptos(u_long_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];

  printf("%s\n",d->name); /* Name */
  if (d->description)
    printf("\tDescription: %s\n",d->description);  /* Description */

  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no"); /* Loopback Address*/
  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);

    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));

        break;

	  case AF_INET6:
		  printf("\tAddress Family Name: AF_INET6\n");
		  break;

	  default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}
void inline print_bw_info(u_short sport, u_int tcb_index)
{
#ifdef DEBUG
	printf("STATE %d BUFFER %u %u ACK %u INTERARRIVAL TIME %u RTT %u RTO %u RTT STD %u SENDING RATE %u AGGREGATE ESTIMATED RATE %u INDIVIDUAL APPROX ESTIMATED RATE %u INDIVIDUAL INSTAN ESTIMATED RATE %u CONNID %hu\n",
			tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd,
			tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size(), tcb_table[tcb_index]->conn[sport]->server_state.snd_una,
			tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->rto,
			tcb_table[tcb_index]->conn[sport]->rtt_std_dev, tcb_table[tcb_index]->send_rate, tcb_table[tcb_index]->rcv_thrughput_approx,
			tcb_table[tcb_index]->send_rate_upper, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, sport);
#endif
}
u_short inline CheckSum(u_short * buffer, u_int size)
{
    u_long_long cksum = 0;

    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size)
    {
        cksum += *(u_char *) buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (u_short) (~cksum);
}
void inline init_retx_data_pkt(u_int tcb_index, u_short sport, u_int num_init)
{
	u_int index = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
	ForwardPkt *retx_pkt;

	for (u_int i = 0; i < num_init; i ++)
	{
		retx_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(index);
		retx_pkt->snd_time = 0;
		index = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pktNext(index);
	}
}
void inline send_forward(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data)
{
	pthread_mutex_lock(&data->forward->mutex);
	while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
	ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
	tmpForwardPkt->data = (void *)data;
	memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
	data->forward->pktQueue.tailNext();
	data->forward->pktQueue.increase();
	pthread_cond_signal(&data->forward->m_eventElementAvailable);
	pthread_mutex_unlock(&data->forward->mutex);
}
void inline send_wait_forward(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data) // test with wifi
{
        pthread_mutex_lock(&data->forward->mutex);
        while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
                pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
        ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
        tmpForwardPkt->data = (void *)data;
        tmpForwardPkt->dPort = 18;
        memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
        memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
        data->forward->pktQueue.tailNext();
        data->forward->pktQueue.increase();
        pthread_cond_signal(&data->forward->m_eventElementAvailable);
        pthread_mutex_unlock(&data->forward->mutex);
}
void inline send_backward(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data)
{
	pthread_mutex_lock(&data->forward_back->mutex);
	while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);

	ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
	tmpForwardPkt->data = (void *)data;
	memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
	data->forward_back->pktQueue.tailNext();
	data->forward_back->pktQueue.increase();
	pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
	pthread_mutex_unlock(&data->forward_back->mutex);
}
void inline send_data_pkt(Forward* forward, ForwardPkt* tmpPkt)
{
	pthread_mutex_lock(&forward->mutex);
	while (forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&forward->m_eventSpaceAvailable, &forward->mutex);
	ForwardPkt *tmpForwardPkt = forward->pktQueue.tail();
	tmpForwardPkt->tcb = tmpPkt->tcb;
	tmpForwardPkt->index = tmpPkt->index;
	tmpForwardPkt->sPort = tmpPkt->sPort;
	tmpForwardPkt->dPort = tmpPkt->dPort;
	tmpForwardPkt->seq_num = tmpPkt->seq_num;
	tmpForwardPkt->data_len = tmpPkt->data_len;
	tmpForwardPkt->data = tmpPkt->data;
	memcpy(&(tmpForwardPkt->header), &(tmpPkt->header), sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, tmpPkt->pkt_data, tmpPkt->header.len);
	forward->pktQueue.tailNext();
	forward->pktQueue.increase();
	pthread_cond_signal(&forward->m_eventElementAvailable);
	pthread_mutex_unlock(&forward->mutex);

}
void inline send_ack_back(u_short dport, DATA* data, ip_address src_address, ip_address dst_address, u_char src_mac[], u_char dst_mac[], u_short src_port, u_short dst_port, u_int seq, u_int ack, u_short ctr_bits, u_short awin, u_short data_id, sack_header* sack)
{
	mac_header macHeader;
	ip_header ipHeader;
	tcp_header tcpHeader;

	psd_header psdHeader;
	struct pcap_pkthdr capHeader;


	if (sack->size())
	{
		tcp_sack tcpSackHeader;
		tcpSackHeader.pad_1 = 1;
		tcpSackHeader.pad_2 = 1;
		tcpSackHeader.kind = 5;
		tcpSackHeader.length = sack->size()*8+2;

		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + sizeof(tcp_sack)] = {0};
		u_short buffer_len;

		buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2;
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;

		for (int i = 0; i < sack->size(); i ++)
		{
			tcpSackHeader.sack_block[i].left_edge_block = htonl(sack->sack_list[i].left_edge_block);
			tcpSackHeader.sack_block[i].right_edge_block = htonl(sack->sack_list[i].right_edge_block);

		}

		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;

		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;
		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);

		//tcpSackHeader.length = sack->size()*8+2 + (4-(sack->size()*8+2)%4);
		tcpHeader.hdr_len_resv_code = htons((sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2) / 4 << 12 | ctr_bits);

		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(psd_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);
		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header) + (u_short)tcpSackHeader.length + 2);

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);

		pthread_mutex_lock(&data->forward_back->mutex);
		while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);
		ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward_back->pktQueue.tailNext();
		data->forward_back->pktQueue.increase();
		pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward_back->mutex);


	}
	else
	{

		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header)] = {0};
		u_short buffer_len;

		buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header);
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;

		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;

		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;

		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);
		tcpHeader.hdr_len_resv_code = htons(sizeof(tcp_header)/4 << 12 | ctr_bits);
		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header));

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));

		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header));


		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));

		pthread_mutex_lock(&data->forward_back->mutex);
		while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);

		ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward_back->pktQueue.tailNext();
		data->forward_back->pktQueue.increase();
		pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward_back->mutex);

	}
}
void inline send_syn_ack_back(u_short dport, DATA* data, ip_address src_address, ip_address dst_address, u_char src_mac[], u_char dst_mac[], u_short src_port, u_short dst_port, u_int seq, u_int ack, u_short ctr_bits, u_short awin, u_short data_id, u_char* tcp_opt, u_short tcp_opt_len, u_char Buffer[])
{
	mac_header macHeader;
	ip_header ipHeader;
	tcp_header tcpHeader;

	psd_header psdHeader;

	struct pcap_pkthdr capHeader;

	u_short buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + tcp_opt_len;

	//u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + 50] = {0};
	//u_char* Buffer = (u_char *)malloc(sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + tcp_opt_len); //
	memset(Buffer, 0, MTU);

	capHeader.ts.tv_sec = time(NULL);
	capHeader.ts.tv_usec = 0;
	capHeader.caplen = buffer_len;
	capHeader.len = buffer_len;

	memcpy(macHeader.mac_src, src_mac, 6);
	memcpy(macHeader.mac_dst, dst_mac, 6);
	macHeader.opt = htons(0x0800);

	ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
	ipHeader.tos = 0;
	ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header) + tcp_opt_len);
	ipHeader.identification = htons(data_id);
	ipHeader.flags_fo = 0x40;
	ipHeader.ttl = 128;
	ipHeader.proto = IPPROTO_TCP;
	ipHeader.crc = 0;
	ipHeader.saddr = src_address;
	ipHeader.daddr = dst_address;

	tcpHeader.sport = htons(src_port);
	tcpHeader.dport = htons(dst_port);
	tcpHeader.seq_num = htonl(seq);
	tcpHeader.ack_num = htonl(ack);
	tcpHeader.hdr_len_resv_code = htons((sizeof(tcp_header) + tcp_opt_len) / 4 << 12 | ctr_bits);
	tcpHeader.window = htons(awin);
	tcpHeader.crc = 0;
	tcpHeader.urg_pointer = 0;

	psdHeader.saddr = src_address;
	psdHeader.daddr = dst_address;
	psdHeader.mbz = 0;
	psdHeader.ptoto = IPPROTO_TCP;
	psdHeader.tcp_len = htons(sizeof(tcp_header) + tcp_opt_len);

	memcpy(Buffer, &psdHeader, sizeof(psd_header));
	memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
	memcpy(Buffer + sizeof(psd_header) + sizeof(tcp_header), tcp_opt, tcp_opt_len);
	tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + tcp_opt_len + sizeof(psd_header));

	memset(Buffer, 0, MTU);
	memcpy(Buffer, &ipHeader, sizeof(ip_header));
	ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

	memset(Buffer, 0, MTU);
	memcpy(Buffer, &macHeader, sizeof(mac_header));
	memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
	memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
	memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header), tcp_opt, tcp_opt_len);

	pthread_mutex_lock(&data->forward_back->mutex);
	while (data->forward_back->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
		pthread_cond_wait(&data->forward_back->m_eventSpaceAvailable, &data->forward_back->mutex);
	ForwardPkt *tmpForwardPkt = data->forward_back->pktQueue.tail();
	tmpForwardPkt->data = (void *)data;
	memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
	data->forward_back->pktQueue.tailNext();
	data->forward_back->pktQueue.increase();
	pthread_cond_signal(&data->forward_back->m_eventElementAvailable);
	pthread_mutex_unlock(&data->forward_back->mutex);

}
void inline send_win_update_forward(u_short dport, DATA* data, ip_address src_address, ip_address dst_address, u_char src_mac[], u_char dst_mac[], u_short src_port, u_short dst_port, u_int seq, u_int ack, u_short ctr_bits, u_short awin, u_short data_id, sack_header* sack)
{
	mac_header macHeader;
	ip_header ipHeader;
	tcp_header tcpHeader;

	psd_header psdHeader;

	struct pcap_pkthdr capHeader;


	if (sack->size())
	{
		tcp_sack tcpSackHeader;
		tcpSackHeader.pad_1 = 1;
		tcpSackHeader.pad_2 = 1;
		tcpSackHeader.kind = 5;
		tcpSackHeader.length = sack->size()*8 + 2;

		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + sizeof(tcp_sack)] = {0};
		u_short buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2;
		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;
		for (int i = 0; i < sack->size(); i ++)
		{
			tcpSackHeader.sack_block[i].left_edge_block = htonl(sack->sack_list[i].left_edge_block);
			tcpSackHeader.sack_block[i].right_edge_block = htonl(sack->sack_list[i].right_edge_block);
		}
		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;
		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);
		tcpHeader.hdr_len_resv_code = htons((sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2)/4 << 12 | ctr_bits);
		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header) + (u_short)tcpSackHeader.length + 2);

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(psd_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);

		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header) + (u_short)tcpSackHeader.length + 2);
		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header), &tcpSackHeader, (u_short)tcpSackHeader.length + 2);

		pthread_mutex_lock(&data->forward->mutex);
		while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
		ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward->pktQueue.tailNext();
		data->forward->pktQueue.increase();
		pthread_cond_signal(&data->forward->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward->mutex);

	}
	else
	{
		u_char Buffer[sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header)] = {0};
		u_short buffer_len = sizeof(mac_header) + sizeof(ip_header) + sizeof(tcp_header);

		capHeader.ts.tv_sec = time(NULL);
		capHeader.ts.tv_usec = 0;
		capHeader.caplen = buffer_len;
		capHeader.len = buffer_len;
		memcpy(macHeader.mac_src, src_mac, 6);
		memcpy(macHeader.mac_dst, dst_mac, 6);
		macHeader.opt = htons(0x0800);

		ipHeader.ver_ihl = (4 << 4 | sizeof(ip_header)/sizeof(u_int));
		ipHeader.tos = 0;
		ipHeader.tlen = htons(sizeof(ip_header) + sizeof(tcp_header));
		ipHeader.identification = htons(data_id);
		ipHeader.flags_fo = 0x40;
		ipHeader.ttl = 128;
		ipHeader.proto = IPPROTO_TCP;
		ipHeader.crc = 0;
		ipHeader.saddr = src_address;
		ipHeader.daddr = dst_address;

		tcpHeader.sport = htons(src_port);
		tcpHeader.dport = htons(dst_port);
		tcpHeader.seq_num = htonl(seq);
		tcpHeader.ack_num = htonl(ack);
		tcpHeader.hdr_len_resv_code = htons(sizeof(tcp_header)/4 << 12 | ctr_bits);
		tcpHeader.window = htons(awin);
		tcpHeader.crc = 0;
		tcpHeader.urg_pointer = 0;

		psdHeader.saddr = src_address;
		psdHeader.daddr = dst_address;
		psdHeader.mbz = 0;
		psdHeader.ptoto = IPPROTO_TCP;
		psdHeader.tcp_len = htons(sizeof(tcp_header));

		memcpy(Buffer, &psdHeader, sizeof(psd_header));
		memcpy(Buffer + sizeof(psd_header), &tcpHeader, sizeof(tcp_header));
		tcpHeader.crc = CheckSum((u_short *)Buffer, sizeof(tcp_header) + sizeof(psd_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &ipHeader, sizeof(ip_header));
		ipHeader.crc = CheckSum((u_short *)Buffer, sizeof(ip_header));

		memset(Buffer, 0, sizeof(Buffer));
		memcpy(Buffer, &macHeader, sizeof(mac_header));
		memcpy(Buffer + sizeof(mac_header), &ipHeader, sizeof(ip_header));
		memcpy(Buffer + sizeof(mac_header) + sizeof(ip_header), &tcpHeader, sizeof(tcp_header));

		pthread_mutex_lock(&data->forward->mutex);
		while (data->forward->pktQueue.size() >= CIRCULAR_QUEUE_SIZE)
			pthread_cond_wait(&data->forward->m_eventSpaceAvailable, &data->forward->mutex);
		ForwardPkt *tmpForwardPkt = data->forward->pktQueue.tail();
		tmpForwardPkt->data = (void *)data;
		memcpy(&(tmpForwardPkt->header), &capHeader, sizeof(struct pcap_pkthdr));
		memcpy(tmpForwardPkt->pkt_data, Buffer, buffer_len);
		data->forward->pktQueue.tailNext();
		data->forward->pktQueue.increase();
		pthread_cond_signal(&data->forward->m_eventElementAvailable);
		pthread_mutex_unlock(&data->forward->mutex);
	}
}
void inline frag_data_pkt(ForwardPkt *frag_pkt, u_int ack_num)
{
	u_char pkt_buffer[MTU];
	mac_header* mh = (mac_header *)frag_pkt->pkt_data;

	ip_header* ih = (ip_header *) (frag_pkt->pkt_data + 14);
	u_int ip_len = (ih->ver_ihl & 0xf) * 4;
	u_short total_len = ntohs(ih->tlen);
	u_short id = ntohs(ih->identification);

	tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
	u_short sport = ntohs(th->sport);
	u_short dport = ntohs(th->dport);
	u_int seq_num = ntohl(th->seq_num);
	//u_int ack_num = ntohl(th->ack_num);

	u_short window = ntohs(th->window);
	u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
	u_short ctr_flag = ntohs(th->hdr_len_resv_code)&0x003f;
	u_short data_len = total_len - ip_len - tcp_len;


	assert(seq_num < ack_num);

	memcpy(ih + tcp_len, ih + tcp_len + (ack_num - seq_num), data_len - (ack_num - seq_num));
	frag_pkt->header.len = 14 + total_len - (ack_num - seq_num);
	ih->tlen = htons(total_len - (ack_num - seq_num));

	data_len = data_len - (ack_num - seq_num);

	th->seq_num = htonl(ack_num);
	th->crc = 0;

	memset(pkt_buffer, 0, MTU);
	psd_header psdHeader;

	psdHeader.saddr = ih->saddr;
	psdHeader.daddr = ih->daddr;
	psdHeader.mbz = 0;
	psdHeader.ptoto = IPPROTO_TCP;
	psdHeader.tcp_len = htons(tcp_len + data_len);

	memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
	memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);

	th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);

	ih->crc = 0;
	memset(pkt_buffer, 0, MTU);
	memcpy(pkt_buffer, ih, ip_len);

	ih->crc = CheckSum((u_short *)pkt_buffer, ip_len);

	frag_pkt->seq_num = ack_num;
	frag_pkt->data_len = data_len;
}
void inline RTT_estimator(ForwardPkt *unAckPkt, u_long_long snd_time, u_long_long rcv_time, u_int ack_num, u_short sport, u_int tcb_index)
{
#ifdef LINUX_RTT
	if (tcb_table[tcb_index]->conn[sport]->RTT)
	{
		if (ack_num <= tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno)
		{
			if (rcv_time - snd_time < tcb_table[tcb_index]->conn[sport]->RTT && abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) > tcb_table[tcb_index]->conn[sport]->mdev)
				tcb_table[tcb_index]->conn[sport]->mdev = (tcb_table[tcb_index]->conn[sport]->mdev >= 0.96875 * tcb_table[tcb_index]->conn[sport]->mdev + 0.03125 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) ? tcb_table[tcb_index]->conn[sport]->mdev : 0.96875 * tcb_table[tcb_index]->conn[sport]->mdev + 0.03125 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))));
			else
				tcb_table[tcb_index]->conn[sport]->mdev = (tcb_table[tcb_index]->conn[sport]->mdev >= 0.75 * tcb_table[tcb_index]->conn[sport]->mdev + 0.25 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) ? tcb_table[tcb_index]->conn[sport]->mdev : 0.75 * tcb_table[tcb_index]->conn[sport]->mdev + 0.25 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))));

		}
		else if (ack_num > tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno && tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts())
		{
			tcb_table[tcb_index]->conn[sport]->rtt_std_dev = tcb_table[tcb_index]->conn[sport]->mdev;
			if (rcv_time - snd_time < tcb_table[tcb_index]->conn[sport]->RTT && abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time))) > tcb_table[tcb_index]->conn[sport]->mdev)
				tcb_table[tcb_index]->conn[sport]->mdev = 0.96875 * tcb_table[tcb_index]->conn[sport]->mdev + 0.03125 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time)));
			else
				tcb_table[tcb_index]->conn[sport]->mdev = 0.75 * tcb_table[tcb_index]->conn[sport]->mdev + 0.25 * abs((long)(tcb_table[tcb_index]->conn[sport]->RTT - (rcv_time - snd_time)));

			tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;
		}


		tcb_table[tcb_index]->conn[sport]->RTT = 0.875 * tcb_table[tcb_index]->conn[sport]->RTT + 0.125 * (rcv_time - snd_time);
		tcb_table[tcb_index]->conn[sport]->LAST_RTT = rcv_time - snd_time;

		tcb_table[tcb_index]->RTT = 0.875 * tcb_table[tcb_index]->RTT + 0.125 * (rcv_time - snd_time);
		tcb_table[tcb_index]->conn[sport]->rto = (MAX_RTO >= tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev ? MAX_RTO : tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev);

	}
	else
	{
		tcb_table[tcb_index]->conn[sport]->RTT = rcv_time - snd_time;
		tcb_table[tcb_index]->conn[sport]->LAST_RTT = rcv_time - snd_time;

		tcb_table[tcb_index]->RTT = rcv_time - snd_time;
		tcb_table[tcb_index]->conn[sport]->rtt_std_dev = tcb_table[tcb_index]->conn[sport]->RTT / 2;
		tcb_table[tcb_index]->conn[sport]->mdev = tcb_table[tcb_index]->conn[sport]->RTT / 2;
		tcb_table[tcb_index]->conn[sport]->rto = (MAX_RTO >= tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev ? MAX_RTO : tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev);
		tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

	}
#endif

#ifdef STD_RTT
	if (tcb_table[tcb_index]->conn[sport]->RTT_IETF)
	{
		if (ack_num > tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno_ietf)
		{
			tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf = 0.75 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf + 0.25 * abs(((long)(rcv_time - snd_time) - tcb_table[tcb_index]->conn[sport]->RTT_IETF));
			tcb_table[tcb_index]->conn[sport]->RTT_IETF = 0.875 * tcb_table[tcb_index]->conn[sport]->RTT_IETF + 0.125 * (rcv_time - snd_time);
			tcb_table[tcb_index]->RTT = 0.875 * tcb_table[tcb_index]->RTT + 0.125 * (rcv_time - snd_time);
			tcb_table[tcb_index]->conn[sport]->LAST_RTT = rcv_time - snd_time;
			tcb_table[tcb_index]->conn[sport]->rto_ietf = (MAX_RTO_IETF >= tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf ? MAX_RTO_IETF : tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf);
			tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno_ietf = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

		}

	}
	else
	{
		tcb_table[tcb_index]->conn[sport]->RTT_IETF = rcv_time - snd_time;
		tcb_table[tcb_index]->RTT = rcv_time - snd_time;
		tcb_table[tcb_index]->conn[sport]->LAST_RTT = tcb_table[tcb_index]->conn[sport]->RTT_IETF;
		tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf = tcb_table[tcb_index]->conn[sport]->RTT_IETF / 2;
		tcb_table[tcb_index]->conn[sport]->rto_ietf = (MAX_RTO_IETF >= tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf ? MAX_RTO_IETF : tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf);
		tcb_table[tcb_index]->conn[sport]->nxt_timed_seqno_ietf = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

	}
#endif

}
void inline BW_adaptation(u_short sport, u_int tcb_index)
{
	if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL && tcb_table[tcb_index]->conn[sport]->RTT)
	{
	        if (tcb_table[tcb_index]->conn[sport]->RTT >= 1000000)
	        {
	            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
                    {
                            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
                            print_bw_info(sport, tcb_index);
                    }
	            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
                    {
                            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
                            print_bw_info(sport, tcb_index);
                    }
	        }
	        else if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit)
		{
			if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
			{
				tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
				print_bw_info(sport, tcb_index);
			}
		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit)
		{
			if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else
			{
				//if (tcb_table[tcb_index]->send_rate <= tcb_table[tcb_index]->rcv_thrughput_approx + 100000)
					tcb_table[tcb_index]->send_rate = 0.1 * tcb_table[tcb_index]->send_rate_upper + 0.9 * tcb_table[tcb_index]->send_rate;
				//else
				//	tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;

				print_bw_info(sport, tcb_index);

			}
		}

	}
	else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX && tcb_table[tcb_index]->conn[sport]->RTT)
	{
	        if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
		{
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
			print_bw_info(sport, tcb_index);
		}
		else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
		{
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
			print_bw_info(sport, tcb_index);
		}
		else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
		{
			tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
			print_bw_info(sport, tcb_index);
		}
	}
}
void inline BandwidthAdaptation(u_int tcb_index)
{
    if (tcb_table[tcb_index]->RTT)
    {
        if (tcb_table[tcb_index]->RTT >= 1000000)
        {
            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
            {
                    tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;

            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
            {
                    tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;

            }
        }
        else if (tcb_table[tcb_index]->RTT >= tcb_table[tcb_index]->RTT_limit)
        {
            if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
            }
            else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
            {
                tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
            }
        }
        else if (tcb_table[tcb_index]->RTT < tcb_table[tcb_index]->RTT_limit)
        {
            if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
            {
                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
            }
            else
            {

                //if (tcb_table[tcb_index]->send_rate <= tcb_table[tcb_index]->rcv_thrughput_approx + 100000)
                        tcb_table[tcb_index]->send_rate = 0.1 * tcb_table[tcb_index]->send_rate_upper + 0.9 * tcb_table[tcb_index]->send_rate;
                //else
                //	tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;

            }

        }

    }
}
void inline tcb_bw_burst_ctrl(u_int tcb_index, u_long_long current_time, u_int sport)
{

#ifdef FIX_TIME_INTERVAL_EST

	if (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) >= SLIDE_TIME_INTERVAL)
	{
		tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time));

		tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

		tcb_table[tcb_index]->sliding_avg_window.nextEstmateSampleTime(current_time);
		tcb_table[tcb_index]->sliding_avg_window.another_shift();


#ifdef DYNAMIC_RATE_FIT

		BandwidthAdaptation(tcb_index);

#endif
	}
	else if (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) < SLIDE_TIME_INTERVAL - SLIDE_TIME_DELTA)
	{
		tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.estmateInterval(current_time));

		tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT

		BandwidthAdaptation(tcb_index);

#endif

	}

#else
	if (current_time > tcb_table[tcb_index]->sliding_avg_window.tailTime() + 5)
	{
		tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));

		tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT

		BandwidthAdaptation(tcb_index);
#endif

	}
#endif



}
void inline log_data(u_short sport, u_int tcb_index)
{
	if (!tcb_table[tcb_index]->conn[sport]->rttFd)
	{
		char name[20];
		sprintf(name, "%u", sport);
		tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
	}

	fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->RTT_IETF, tcb_table[tcb_index]->conn[sport]->mdev, tcb_table[tcb_index]->conn[sport]->RTT + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev, tcb_table[tcb_index]->conn[sport]->RTT_IETF + 4 * tcb_table[tcb_index]->conn[sport]->rtt_std_dev_ietf, tcb_table[tcb_index]->conn[sport]->rto, tcb_table[tcb_index]->conn[sport]->rto_ietf, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->rcv_thrughput_approx, tcb_table[tcb_index]->rcv_thrughput, tcb_table[tcb_index]->send_rate, tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytes(), tcb_table[tcb_index]->conn[sport]->max_data_len);
}
u_int inline aggre_bw_estimate_approx(u_short this_port, u_int tcb_index)
{
	u_long_long current_time = timer.Start();

	u_int sport;
	tcb_table[tcb_index]->aggre_bw_estimate = 0;

	for (u_int i = 0; i < tcb_table[tcb_index]->states.num; i ++)
	{
		if (tcb_table[tcb_index]->states.state_id[i] != this_port)
		{
			sport = tcb_table[tcb_index]->states.state_id[i];
			tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time) == 0 ? 0 :
				tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytesCount() * RESOLUTION / tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time));
			tcb_table[tcb_index]->aggre_bw_estimate += tcb_table[tcb_index]->conn[sport]->rcv_thrughput;
		}
	}

	tcb_table[tcb_index]->aggre_bw_estimate += tcb_table[tcb_index]->conn[this_port]->rcv_thrughput_approx;
	return tcb_table[tcb_index]->aggre_bw_estimate;
}
void inline ack_sack_option(u_char* tcp_opt, u_int tcp_opt_len, u_short sport, u_int ack_num, u_int tcb_index)
{
        for (u_int i = 0; i < tcp_opt_len; )
        {
            switch ((u_short)*(tcp_opt + i))
            {
            case 0: //end of option
                    *(tcp_opt + i) = 1;
                    //printf("END OF OPTION\n");
                    break;
            case 1: //NOP
                    //printf("NO OF OPERATION\n");
                    break;
            case 5: //SACK

                    u_short sack_block_num = ((u_short)*(tcp_opt + i + 1) - 2) / sizeof(tcp_sack_block);
                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;

                    if (sack_block_num == 1) // init sack_block_num
                    	tcb_table[tcb_index]->conn[sport]->sack_block_num = sack_block_num;

                    if (sack_block_num > tcb_table[tcb_index]->conn[sport]->sack_block_num && sack_block_num >= 2)
                    {
                    	u_int last_right_sack = ntohl(*(u_int *)(tcp_opt + i + 2 + 1*8 + 4));

                    	if (MY_SEQ_LT(ack_num, last_right_sack) && tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX) // DSACK
                    	{
                    		ForwardPkt* out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                    		if (MY_SEQ_GT(out_awin_pkt->seq_num, ack_num + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                    		{
                    			while (MY_SEQ_GT(out_awin_pkt->seq_num, ack_num + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale) + last_right_sack - ack_num))
                    			{
                    				 tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                    				 out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                    				 tcb_table[tcb_index]->pkts_transit --;
                    			}
                    		}
                    	}
                    }

                    tcb_table[tcb_index]->conn[sport]->sack_block_num = sack_block_num;

                    u_int left_sack, right_sack;
                    u_int rtx = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;

                    ForwardPkt* is_rtx_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(rtx);

                    for (int j = sack_block_num - 1; j >= 0; j --)
                    {
                        left_sack = ntohl(*(u_int *)(tcp_opt + i + 2 + j*8));
                        right_sack = ntohl(*(u_int *)(tcp_opt + i + 2 + j*8 + 4));

                        if (MY_SEQ_GEQ(ack_num, right_sack)) //DSACK
                        {
                            tcb_table[tcb_index]->conn[sport]->sack_diff += (int)(right_sack - left_sack);

                            continue;
                        }

                        while (is_rtx_pkt->occupy && MY_SEQ_LT(is_rtx_pkt->seq_num, right_sack))
                        {
							if (MY_SEQ_GEQ(is_rtx_pkt->seq_num, left_sack) && MY_SEQ_LEQ(is_rtx_pkt->seq_num + is_rtx_pkt->data_len, right_sack) && is_rtx_pkt->is_rtx)
                            {
                                is_rtx_pkt->is_rtx = false;
                                tcb_table[tcb_index]->conn[sport]->sack_diff += is_rtx_pkt->data_len;
                                tcb_table[tcb_index]->conn[sport]->undup_sack_diff += is_rtx_pkt->data_len;

                            }

                            rtx = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pktNext(rtx);
                            is_rtx_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(rtx);

                        }

                        if (MY_SEQ_GT(right_sack, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
                        {
                            tcb_table[tcb_index]->conn[sport]->max_sack_edge = right_sack;
                        }

                        /*
                        u_short m = 0;
                        while (TRUE)
                        {
                            if (tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block == 0 && tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block == 0)
                            {
                                tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block = left_sack;
                                tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block = right_sack;
                                tcb_table[tcb_index]->conn[sport]->sack_block_num ++;
                                tcb_table[tcb_index]->conn[sport]->sack_diff += (int)(right_sack - left_sack);
                                tcb_table[tcb_index]->conn[sport]->undup_sack_diff += (int)(right_sack - left_sack);
                                break;
                            }
                            else if ((tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block == left_sack && tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block != right_sack) || (tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block != left_sack && tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block == right_sack))
                            {
                                tcb_table[tcb_index]->conn[sport]->sack_diff += ((int)(right_sack - left_sack) - (int)(tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block - tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block));
                                tcb_table[tcb_index]->conn[sport]->undup_sack_diff += ((int)(right_sack - left_sack) - (int)(tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block - tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block));
                                tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block = left_sack;
                                tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block = right_sack;

                                break;
                            }
                            else if (tcb_table[tcb_index]->conn[sport]->sack_block[m].left_edge_block == left_sack && tcb_table[tcb_index]->conn[sport]->sack_block[m].right_edge_block == right_sack)
                            {
                                break;
                            }

                            m ++;
                            if (m == NUM_SACK_BLOCK)
                            {
                                m = 0;
                                u_short target = tcb_table[tcb_index]->conn[sport]->sack_target_block;
                                tcb_table[tcb_index]->conn[sport]->sack_block[target].left_edge_block = left_sack;
                                tcb_table[tcb_index]->conn[sport]->sack_block[target].right_edge_block = right_sack;
                                tcb_table[tcb_index]->conn[sport]->sack_diff += (int)(right_sack - left_sack);
                                tcb_table[tcb_index]->conn[sport]->undup_sack_diff += (int)(right_sack - left_sack);
                                tcb_table[tcb_index]->conn[sport]->sack_target_block ++;

                                if (tcb_table[tcb_index]->conn[sport]->sack_target_block == NUM_SACK_BLOCK)
                                    tcb_table[tcb_index]->conn[sport]->sack_target_block = 0;
                                break;
                            }
                        }
                        */
                    }

                    break;
            }

            if ((u_short)*(tcp_opt + i) > 1)
               i += (u_short)*(tcp_opt + i + 1);
            else
               i ++;
        }


}
void inline rcv_ack_bw_estimate(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();

	//if (tcb_table[tcb_index]->conn[sport]->reset_timer == TRUE)
	//	tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == 0)
		tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		//Right version of TCPW bandwidth estimation
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.065 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput :
			0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time));
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);

#ifdef LOG_STAT

		if (!tcb_table[tcb_index]->conn[sport]->rttFd)
		{
			char name[20];
			itoa(sport, name, 10);
			tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
		}

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
			//tcb_table[tcb_index]->send_rate = aggre_bw_estimate_approx(sport, tcb_index);

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 5;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate - 25000)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				print_bw_info(sport, tcb_index);
			}
			/*
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 50000 && tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			*/

		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit / 2 /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else if (0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 20000)
			{
				tcb_table[tcb_index]->send_rate = 0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
		}

#endif

		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}
}
void inline rcv_dup_ack_bw_estimate(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.065 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput :
			0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time));
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->send_rate_lower >= tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx)
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		else
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;

		print_bw_info(sport, tcb_index);
#endif

#ifdef LOG_STAT

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);
#endif
		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;

	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	}

}
void inline rcv_ack_stat_count(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	/*
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	*/
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	//if (tcb_table[tcb_index]->conn[sport]->reset_timer == TRUE)
	//	tcb_table[tcb_index]->conn[sport]->init_state();

	if (!tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time)
		tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		//Wrong version of TCPW bandwidth estimation
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno - tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time;

#ifdef LOG_STAT

		if (!tcb_table[tcb_index]->conn[sport]->rttFd)
		{
			char name[20];
			itoa(sport, name, 10);
			tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
		}

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
			//tcb_table[tcb_index]->send_rate = aggre_bw_estimate_approx(sport, tcb_index);

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 5;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate - 25000)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				print_bw_info(sport, tcb_index);
			}
			/*
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 50000 && tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			*/

		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit / 2 /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else if (0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 20000)
			{
				tcb_table[tcb_index]->send_rate = 0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
		}
#endif

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;
	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		assert(tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time);
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno - tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
	}

}
void inline rcv_dup_ack_stat_count(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		// Wrong version of TCPW of bandwidth estimation
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.935 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx +
			0.0325 * (tcb_table[tcb_index]->conn[sport]->rcv_thrughput + tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = tcb_table[tcb_index]->conn[sport]->cumul_ack * 1000 / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time;

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->send_rate_lower >= tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx)
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		else
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;

		print_bw_info(sport, tcb_index);
#endif

#ifdef LOG_STAT
		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->thruput_actual, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif
		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;

	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	}
}
void inline rcv_ack_dft_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();
	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	//tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = GetTickCount();
	//if (tcb_table[tcb_index]->conn[sport]->reset_timer == TRUE)
	//	tcb_table[tcb_index]->conn[sport]->init_state();

	if (!tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time)
		tcb_table[tcb_index]->conn[sport]->init_state();

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = 0.2 * tcb_table[tcb_index]->conn[sport]->ack_interarrival_time + 0.8 * (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time);
		tcb_table[tcb_index]->conn[sport]->dft_cumul_ack = 0.2 * tcb_table[tcb_index]->conn[sport]->dft_cumul_ack + 0.8 * tcb_table[tcb_index]->conn[sport]->cumul_ack;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->dft_cumul_ack * RESOLUTION / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.9 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.1 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

#ifdef LOG_STAT

		if (!tcb_table[tcb_index]->conn[sport]->rttFd)
		{
			char name[20];
			itoa(sport, name, 10);
			tcb_table[tcb_index]->conn[sport]->rttFd = fopen(strcat(name, "rtt.txt"), "w");
		}

		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%u %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->conn[sport]->RTT >= tcb_table[tcb_index]->conn[sport]->RTT_limit /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
			//tcb_table[tcb_index]->send_rate = aggre_bw_estimate_approx(sport, tcb_index);

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 5;
				print_bw_info(sport, tcb_index);
			}
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate - 25000)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				print_bw_info(sport, tcb_index);
			}
			/*
			else if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 50000 && tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_upper)
			{
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
			*/

		}
		else if (tcb_table[tcb_index]->conn[sport]->RTT < tcb_table[tcb_index]->conn[sport]->RTT_limit / 2 /*&& ack_num >= tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno*/)
		{
			//tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len

			if (tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate_upper)
			{
				//tcb_table[tcb_index]->conn[sport]->RTT_limit -= 1;
				tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
				print_bw_info(sport, tcb_index);
			}
			else if (0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx >= tcb_table[tcb_index]->send_rate + 20000)
			{
				tcb_table[tcb_index]->send_rate = 0.2 * tcb_table[tcb_index]->send_rate_upper + 0.8 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;
				print_bw_info(sport, tcb_index);
			}
		}

#endif

		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->last_ack_seqno - tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no;
	}

}
void inline rcv_dup_ack_dft_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time = timer.Start();


	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;

	if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time != tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = 0.2 * tcb_table[tcb_index]->conn[sport]->ack_interarrival_time + 0.8 * (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->ref_ack_time);
		tcb_table[tcb_index]->conn[sport]->dft_cumul_ack = 0.2 * tcb_table[tcb_index]->conn[sport]->dft_cumul_ack + 0.8 * tcb_table[tcb_index]->conn[sport]->cumul_ack;
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->ack_interarrival_time == 0 ? 0 : tcb_table[tcb_index]->conn[sport]->dft_cumul_ack * RESOLUTION / tcb_table[tcb_index]->conn[sport]->ack_interarrival_time);
		tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.9 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.1 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT

		if (tcb_table[tcb_index]->send_rate_lower >= tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx)
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		else
			tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx;

		print_bw_info(sport, tcb_index);
#endif

#ifdef LOG_STAT
		fprintf(tcb_table[tcb_index]->conn[sport]->rttFd, "%lu %u %u %u %u %u %u\n", tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->cumul_ack, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx, tcb_table[tcb_index]->conn[sport]->rcv_thrughput);

#endif
		tcb_table[tcb_index]->conn[sport]->ref_ack_seq_no = tcb_table[tcb_index]->conn[sport]->last_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->ref_ack_time = tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time;

		tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
		tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;

	}
	else if (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time == tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack += tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	}

}
void inline rcv_ack_slide_win_avg_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{

	tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time > 0 ? tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time : 0);
	tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;

	tcb_table[tcb_index]->conn[sport]->cur_ack_seqno = ack_num;
	tcb_table[tcb_index]->conn[sport]->last_ack_seqno = (tcb_table[tcb_index]->conn[sport]->last_ack_seqno == 0 ? ack_num : tcb_table[tcb_index]->conn[sport]->last_ack_seqno);

	tcb_table[tcb_index]->conn[sport]->cumul_ack = (int)(tcb_table[tcb_index]->conn[sport]->cur_ack_seqno - tcb_table[tcb_index]->conn[sport]->last_ack_seqno);

	if (tcb_table[tcb_index]->conn[sport]->cumul_ack > tcb_table[tcb_index]->conn[sport]->max_data_len)
	{
		if (tcb_table[tcb_index]->conn[sport]->accounted_for >= tcb_table[tcb_index]->conn[sport]->cumul_ack)
		{
			tcb_table[tcb_index]->conn[sport]->accounted_for = tcb_table[tcb_index]->conn[sport]->accounted_for - tcb_table[tcb_index]->conn[sport]->cumul_ack;
			tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->max_data_len;
		}
		else
		{
			tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->cumul_ack - tcb_table[tcb_index]->conn[sport]->accounted_for;
			tcb_table[tcb_index]->conn[sport]->accounted_for = 0;
		}
	}

	tcb_table[tcb_index]->conn[sport]->sliding_avg_win.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, ack_num);
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytesCount() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time));

	tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

#ifdef FIX_TIME_INTERVAL_EST

	if(!tcb_table[tcb_index]->sliding_avg_window.sample_time)
	{
		tcb_table[tcb_index]->sliding_avg_window.sample_time = current_time;
	}
	tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, ack_num);


	/*
	if (current_time < tcb_table[tcb_index]->sliding_avg_window.frontTime() + SLIDE_TIME_INTERVAL)
	{
		tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));

		tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT
		BW_adaptation(sport, tcb_index);
#endif

	}
	*/

#else

	tcb_table[tcb_index]->sliding_avg_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, ack_num);
	tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));
	tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;

#ifdef DYNAMIC_RATE_FIT
	BW_adaptation(sport, tcb_index);
#endif
#ifndef DEBUG
		printf("%d  %u  %u  %u  %u  %u  %u  %u %hu\t\t\t\t\t\r", tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time/1000, tcb_table[tcb_index]->conn[sport]->RTT/1000, tcb_table[tcb_index]->conn[sport]->RTT_limit/1000, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, sport);
#endif
#endif

#ifdef LOG_STAT
	log_data(sport, tcb_index);
#endif
	tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
	tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;

}
void inline rcv_dup_ack_slide_win_avg_bw(u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{
	tcb_table[tcb_index]->conn[sport]->ack_interarrival_time = (tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time > 0 ? tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time - tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time : 0);
	tcb_table[tcb_index]->conn[sport]->last_ack_rcv_time = tcb_table[tcb_index]->conn[sport]->cur_ack_rcv_time;

	if (tcb_table[tcb_index]->conn[sport]->sack_diff)
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack = tcb_table[tcb_index]->conn[sport]->sack_diff;
		tcb_table[tcb_index]->conn[sport]->accounted_for = tcb_table[tcb_index]->conn[sport]->accounted_for + tcb_table[tcb_index]->conn[sport]->cumul_ack;

	}
	else
	{
		tcb_table[tcb_index]->conn[sport]->cumul_ack = 1024/*tcb_table[tcb_index]->conn[sport]->max_data_len*/;
		tcb_table[tcb_index]->conn[sport]->accounted_for = tcb_table[tcb_index]->conn[sport]->accounted_for + tcb_table[tcb_index]->conn[sport]->cumul_ack;

	}

	tcb_table[tcb_index]->conn[sport]->sliding_avg_win.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput = (tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.bytesCount() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->conn[sport]->sliding_avg_win.timeInterval(current_time));
	tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->conn[sport]->rcv_thrughput;

#ifdef FIX_TIME_INTERVAL_EST

	tcb_table[tcb_index]->sliding_avg_window.another_put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);

#else
	tcb_table[tcb_index]->sliding_avg_window.put(tcb_table[tcb_index]->conn[sport]->cumul_ack, current_time, tcb_table[tcb_index]->conn[sport]->cur_ack_seqno);
	tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? (u_long_long)tcb_table[tcb_index]->send_rate_upper : tcb_table[tcb_index]->sliding_avg_window.bytes() * (u_long_long)RESOLUTION / (u_long_long)tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));
	tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;


#ifdef DYNAMIC_RATE_FIT

	if (tcb_table[tcb_index]->rcv_thrughput_approx < tcb_table[tcb_index]->send_rate_lower)
	{
		tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_lower;
		print_bw_info(sport, tcb_index);
	}
	else if (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate)
	{
		tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->rcv_thrughput_approx;
		print_bw_info(sport, tcb_index);
	}
	else if (tcb_table[tcb_index]->rcv_thrughput_approx > tcb_table[tcb_index]->send_rate)
	{
		tcb_table[tcb_index]->send_rate = (tcb_table[tcb_index]->rcv_thrughput_approx <= tcb_table[tcb_index]->send_rate_upper ? tcb_table[tcb_index]->rcv_thrughput_approx : tcb_table[tcb_index]->send_rate_upper);
		print_bw_info(sport, tcb_index);
	}

#endif

#ifndef DEBUG
    printf("%d  %u  %u  %u  %u  %u  %u  %u %hu\t\t\t\t\t\r", tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time/1000, tcb_table[tcb_index]->conn[sport]->RTT/1000, tcb_table[tcb_index]->conn[sport]->RTT_limit/1000, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, sport);
#endif

#endif
#ifdef LOG_STAT
	log_data(sport, tcb_index);
#endif

	tcb_table[tcb_index]->conn[sport]->last_ack_seqno = tcb_table[tcb_index]->conn[sport]->cur_ack_seqno;
	tcb_table[tcb_index]->conn[sport]->cumul_ack = 0;

}
void inline rcv_ack_handler(u_char* th, u_int tcp_len, u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{
	// ACK sent but unAck packet
	ForwardPkt *unAckPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
	tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;
	tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

	if (tcp_len > 20) // TCP Options Check SACK lists
        {
            u_int tcp_opt_len = tcp_len - 20;
            u_char *tcp_opt = (u_char *)th + 20;
            ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index);
        }

	if ((tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX || tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT))
            if (MY_SEQ_GEQ(ack_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
            {

#ifdef DEBUG
              printf("------ACK %u RECOVER MAX SACK EDGE %u ON CONNECTION %hu------\n", ack_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge, sport);
#endif

              if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
              {
                  //printf("State %u to State %u receiving ACK %u %u Conn %hu\n", FAST_RTX, tcb_table[tcb_index]->conn[sport]->server_state.phase, ack_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge, sport);

                  if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge))
                  {
                      tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge;
                  }
                  else
                  {
                      tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                      tcb_table[tcb_index]->conn[sport]->sack_block_num = 0;
                      //if (!tcb_table[tcb_index]->conn[sport]->send_out_awin)

                      tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;

                      tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;


                      //tcb_table[tcb_index]->conn[sport]->send_out_awin = FALSE;

                      /*
                      tcb_table[tcb_index]->conn[sport]->RTT = 0;
                      tcb_table[tcb_index]->RTT = 0;
                      tcb_table[tcb_index]->conn[sport]->LAST_RTT = tcb_table[tcb_index]->conn[sport]->RTT;
                      tcb_table[tcb_index]->conn[sport]->rtt_std_dev = tcb_table[tcb_index]->conn[sport]->RTT / 2;
                      tcb_table[tcb_index]->conn[sport]->mdev = tcb_table[tcb_index]->conn[sport]->RTT / 2;
                      */
                  }
              }
              else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
              {
                  tcb_table[tcb_index]->conn[sport]->FRTO_ack_count ++;
                  if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1)
                  {
                      if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num, tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->seq_num))
                      {
                          tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                          tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;
                      }

                      if (!unAckPkt->snd_time)
                      {
                          tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                          tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                          tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                      }
                      else
                      {
                          tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                          if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts())
                          {
                              tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num + tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->data_len;
                              tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;

                          }
                          else if (!tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts())
                          {
                              tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->server_state.snd_max + tcb_table[tcb_index]->conn[sport]->max_data_len;
                              tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                          }


                      }

#ifdef DEBUG
                      printf("------RESTORED ACK %u DETECTED BY F-RTO ON CONNECTION %hu-----\n", ack_num, sport);
#endif

                  }
                  else if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 2)
                  {
                      tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                      tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                      tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;

#ifdef DEBUG
                      printf("------RESTORED ACK %u DETECTED BY F-RTO ON CONNECTION %hu-----\n", ack_num, sport);
#endif

                  }
              }
	  }
	  /*
	  else if (MY_SEQ_LT(ack_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
	  {
	     if (tcb_table[tcb_index]->conn[sport]->send_out_awin)
	     {
	         tcb_table[tcb_index]->conn[sport]->send_out_awin = false;
	     }
	  }
          */

	while (unAckPkt->occupy && MY_SEQ_GEQ(ack_num, unAckPkt->seq_num + unAckPkt->data_len))
        {
            tcb_table[tcb_index]->pkts_transit --;
            unAckPkt->rcv_time = current_time;

            if (unAckPkt->seq_num + unAckPkt->data_len == ack_num)
            {
                if (unAckPkt->snd_time && unAckPkt->snd_time < unAckPkt->rcv_time)
                   RTT_estimator(unAckPkt, unAckPkt->snd_time, unAckPkt->rcv_time, ack_num, sport, tcb_index);
                else if (unAckPkt->rtx_time && unAckPkt->rtx_time < unAckPkt->rcv_time)
                   RTT_estimator(unAckPkt, unAckPkt->rtx_time, unAckPkt->rcv_time, ack_num, sport, tcb_index);
            }

            unAckPkt->initPkt();
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAckNext();
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.decrease();
            unAckPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();

        }

	rcv_ack_slide_win_avg_bw(ack_num, window, sport, tcb_index, current_time);

	if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts > tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size)
	{
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck()->seq_num;

            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
            {
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;

            }
	}

	// Adv window is zero, prepare to retransmit,
	if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd <= tcb_table[tcb_index]->conn[sport]->server_state.win_limit)
	{
            tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = FALSE;
            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
	}

}
void inline rcv_dup_ack_handler(u_char* th, u_int tcp_len, u_int ack_num, u_short window, u_short sport, u_int tcb_index, u_long_long current_time)
{
	ForwardPkt* retransmitPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
	tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;
	tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

	if (tcp_len > 20) // TCP Options
    {
	  u_int tcp_opt_len = tcp_len - 20;
	  u_char *tcp_opt = (u_char *)th + 20;
	  ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index);
    }

	if (window)
	{
	    if (tcb_table[tcb_index]->conn[sport]->undup_sack_diff) // send within AWnd
	    {
	    	retransmitPkt->num_dup ++;
	    	//tcb_table[tcb_index]->pkts_transit --;
	    }
	    else if (tcb_table[tcb_index]->conn[sport]->sack_diff) // send before AWnd
	    {
	    	//tcb_table[tcb_index]->pkts_transit --;
	    }
	    else if (!tcb_table[tcb_index]->conn[sport]->undup_sack_diff && !tcb_table[tcb_index]->conn[sport]->sack_diff) // send beyond AWnd
	    {
            retransmitPkt->num_dup ++;
            //tcb_table[tcb_index]->pkts_transit --;
            //tcb_table[tcb_index]->conn[sport]->send_out_awin = TRUE;
	    }
	}
	else if (!window) // AWnd zero
	{
            retransmitPkt->num_dup ++;
            //tcb_table[tcb_index]->pkts_transit --;
            //tcb_table[tcb_index]->conn[sport]->send_out_awin = TRUE;
	}


	if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd <= tcb_table[tcb_index]->conn[sport]->server_state.win_limit)
	{
            tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = FALSE;
            tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper;
	}

	rcv_dup_ack_slide_win_avg_bw(ack_num, window, sport, tcb_index, current_time);

	if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts > tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size)
	{
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck()->seq_num;

            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
            {
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
            }

	}

	if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
	{

            tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count ++;

            /*
            if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 0 && tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count == 1)
            {
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts;

                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                return;

            }
            else */

            if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1 && tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count == 1)
            {
                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;
                tcb_table[tcb_index]->pkts_transit = 0;
                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = retransmitPkt->seq_num;
                retransmitPkt->rtx_time = retransmitPkt->snd_time;
                retransmitPkt->snd_time = 0;

#ifdef DEBUG
                printf("%u %u %u %u %u\n",  tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts, ack_num);
#endif

                return;
            }

	}

	if (retransmitPkt->num_dup == NUM_DUP_ACK)
	{

	    if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
        {
	        if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, retransmitPkt->seq_num + retransmitPkt->data_len))
	        {
	           //tcb_table[tcb_index]->conn[sport]->max_sack_edge = retransmitPkt->seq_num + retransmitPkt->data_len;
	           tcb_table[tcb_index]->conn[sport]->max_sack_edge = retransmitPkt->seq_num +  tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

	        }

                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head;
                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts;


                ForwardPkt *out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();

                if (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                {
                    tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

                    while (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                    {
                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                        out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                        tcb_table[tcb_index]->pkts_transit --;
                    }

                }
                else
                {
                    tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = out_awin_pkt->seq_num;
                }

        }
	    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
	    {

	        if (MY_SEQ_GT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge)) // out-of-AWnd tx successful
            {

	           tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->max_sack_edge;
	           /*
			   ForwardPkt *out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                   while (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                   {
                       tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                       out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                   }
               */

	           tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	           tcb_table[tcb_index]->conn[sport]->undup_sack_diff = 0;

               return;
            }
	        else // out-of-AWnd tx are all failed
	        {
	        	/*
	            ForwardPkt *out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();

	            if (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
	            {

	                tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

                         //tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->max_sack_edge;

                         ForwardPkt *out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();
                         while (MY_SEQ_GT(out_awin_pkt->seq_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                         {

                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadPrev();
                            out_awin_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();

                         }



	            }
	            else
	            {
	                tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = out_awin_pkt->seq_num;
	            }
				*/
	            tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	            tcb_table[tcb_index]->conn[sport]->undup_sack_diff = 0;

	            return;
	        }

	    }

            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = retransmitPkt->seq_num;
            retransmitPkt->rtx_time = retransmitPkt->snd_time;
            retransmitPkt->snd_time = 0;

            tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;

#ifdef DEBUG
            printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO DUP ACKS ON ESTIMATED RATE %u\n", retransmitPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx);
#endif

	}
	else if (retransmitPkt->num_dup > NUM_DUP_ACK)
	{

			if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win && tcb_table[tcb_index]->conn[sport]->sack_block_num && !tcb_table[tcb_index]->conn[sport]->undup_sack_diff && !tcb_table[tcb_index]->conn[sport]->sack_diff)
            {
               if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale)))
                  tcb_table[tcb_index]->conn[sport]->max_sack_edge = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
            }

			tcb_table[tcb_index]->conn[sport]->rcv_max_seq_edge = tcb_table[tcb_index]->conn[sport]->max_sack_edge;

	}

	tcb_table[tcb_index]->conn[sport]->sack_diff = 0;
	tcb_table[tcb_index]->conn[sport]->undup_sack_diff = 0;

}
void inline rcv_data_pkt(DATA* data, struct pcap_pkthdr* header, const u_char* pkt_data, u_short sport, u_short dport, u_int seq_num, u_short data_len, u_short ctr_flag, u_int tcb_index)
{
	ForwardPkt *tmpForwardPkt = tcb_table[tcb_index]->conn[dport]->dataPktBuffer.tail();
	tmpForwardPkt->index = (tcb_table[tcb_index]->conn[dport]->dataPktBuffer._tail % tcb_table[tcb_index]->conn[dport]->dataPktBuffer.capacity);
	tmpForwardPkt->data = (void *)data;
	memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
	memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
	tmpForwardPkt->tcb = tcb_index;
	tmpForwardPkt->sPort = sport;
	tmpForwardPkt->dPort = dport;
#ifdef COMPLETE_SPLITTING_TCP
	tmpForwardPkt->seq_num = tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt;
#else
	tmpForwardPkt->seq_num = seq_num;
#endif
	tmpForwardPkt->data_len = data_len;
	tcb_table[tcb_index]->conn[dport]->max_data_len = max(tcb_table[tcb_index]->conn[dport]->max_data_len, (u_int)data_len);
	tmpForwardPkt->ctr_flag = ctr_flag;
	tmpForwardPkt->snd_time = 0;
	tmpForwardPkt->rcv_time = 0;
	tmpForwardPkt->num_dup = 0;
	tmpForwardPkt->is_rtx = true;
	tmpForwardPkt->occupy = true;
	tcb_table[tcb_index]->conn[dport]->dataPktBuffer.tailNext();
	tcb_table[tcb_index]->conn[dport]->dataPktBuffer.increase();
        tcb_table[tcb_index]->conn[dport]->dataPktBuffer._last_pkts ++;
}
void inline clean_sack(u_short sport, u_int ack_num, u_int tcb_index)
{
	tcb_table[tcb_index]->conn[sport]->sack_block_num = 0;
	tcb_table[tcb_index]->conn[sport]->max_sack_edge = ack_num;
	for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
	{
		if (tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block && tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block)
		{

			tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block = tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block = 0;
		}
	}
}
void inline create_sack_list(u_int tcb_index, u_short dport, u_int seq_num, u_short data_len)
{

	if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() == 0)
	{
		tcb_table[tcb_index]->conn[dport]->client_state.sack._size ++;
		tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[0].left_edge_block = seq_num;
		tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[0].right_edge_block = seq_num + data_len;

		return;
	}
	else
	{
		for (int i = 0; i < tcb_table[tcb_index]->conn[dport]->client_state.sack.size(); i ++)
		{
			if (seq_num < tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
			{
				if (seq_num + data_len < tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
				{
					if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() == CLIENT_SACK_SIZE)
					{
						return;
					}
					else
					{

						tcb_table[tcb_index]->conn[dport]->client_state.sack._size ++;
						for (int j = i + 1; j < tcb_table[tcb_index]->conn[dport]->client_state.sack._size; j ++)
						{
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].left_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].left_edge_block;
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].right_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].right_edge_block;

						}

						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block = seq_num;
						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block = seq_num + data_len;

						return;
					}
				}
				else if (seq_num + data_len >= tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
				{
					tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block = seq_num;

					return;
				}
			}
			else if (seq_num >= tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block)
			{
				if (seq_num == tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block)
				{
					tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block = seq_num + data_len;

					return;
				}
				else if (seq_num > tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block)
				{
					if (i == tcb_table[tcb_index]->conn[dport]->client_state.sack.size() - 1)
					{
						if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() == CLIENT_SACK_SIZE)
						{
							return;
						}
						else
						{
							tcb_table[tcb_index]->conn[dport]->client_state.sack._size ++;
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i+1].left_edge_block = seq_num;
							tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i+1].right_edge_block = seq_num + data_len;

							return;
						}
					}

					continue;
				}
			}
		}
	}

}
u_int inline check_sack_list(u_int tcb_index, u_short dport, u_int seq_num, u_int data_len)
{
	if (tcb_table[tcb_index]->conn[dport]->client_state.sack.size() > 0)
	{
		for (int i = 0; i < tcb_table[tcb_index]->conn[dport]->client_state.sack.size(); i ++)
		{
			if (seq_num < tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
			{
				if (seq_num + data_len >= tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block)
				{
					u_int snd_nxt = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block;

					tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].left_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[i].right_edge_block = 0;

					for (int j = i + 1; j < tcb_table[tcb_index]->conn[dport]->client_state.sack.size(); j ++)
					{
						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].left_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].left_edge_block;
						tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j-1].right_edge_block = tcb_table[tcb_index]->conn[dport]->client_state.sack.sack_list[j].right_edge_block;
					}

					tcb_table[tcb_index]->conn[dport]->client_state.sack._size --;

					return snd_nxt;
				}
			}

		}

	}

	return seq_num + data_len;
}
void inline syn_sack_option(u_char* tcp_opt, u_int tcp_opt_len, u_short dport, BOOL host, u_int tcb_index)
{
	for (u_int i = 0; i < tcp_opt_len; )
	{
		switch ((u_short)*(tcp_opt + i))
		{
		case 0: //end of option
			*(tcp_opt + i) = 1;
			//printf("END OF OPTION\n");
			break;
		case 1: // NOP
			//printf("NO OPERATION\n");
			break;
		case 4: // SACK permitted
			tcb_table[tcb_index]->conn[dport]->server_state.SACK_permitted = TRUE;
#ifdef DEBUG
			printf("SACK_PERMITTED\n");
#endif
			break;
		case 2:
			tcb_table[tcb_index]->conn[dport]->MSS = min(ntohs(*(u_short *)(tcp_opt + i + 2)), tcb_table[tcb_index]->conn[dport]->MSS);
#ifdef DEBUG
			printf("MSS: %u\n", tcb_table[tcb_index]->conn[dport]->MSS);
#endif
			break;
		case 3:
			if (host) //TRUE Server from client
			{
                            tcb_table[tcb_index]->conn[dport]->server_state.win_scale = (u_short)*(tcp_opt + i + 2);
                            *(tcp_opt + i + 2) = WIN_SCALE; // can be 1, 2, 3, 4, 0
                            tcb_table[tcb_index]->conn[dport]->client_state.win_scale = max((u_short)*(tcp_opt + i + 2), tcb_table[tcb_index]->conn[dport]->server_state.win_scale);

#ifdef DEBUG
                            printf("WIN_SCALE: %hu\n", tcb_table[tcb_index]->conn[dport]->server_state.win_scale);
#endif
			}
			else //FALSE Client from Server
			{
			    //tcb_table[tcb_index]->conn[dport]->client_state.win_scale = max((u_short)*(tcp_opt + i + 2), tcb_table[tcb_index]->conn[dport]->server_state.win_scale);
			    *(tcp_opt + i + 2) = 15;
			    tcb_table[tcb_index]->conn[dport]->client_state.sender_win_scale = (u_short)*(tcp_opt + i + 2);
#ifdef DEBUG
			    printf("WIN_SCALE: %hu\n", tcb_table[tcb_index]->conn[dport]->client_state.win_scale);
#endif
			}

			break;
		}

		if ((u_short)*(tcp_opt + i) > 1)
			i += (u_short)*(tcp_opt + i + 1);
		else
			i ++;
	}
}
void inline rcv_header_update(ip_header* ih, tcp_header* th, u_short tcp_len, u_short data_len)
{
	u_char Buffer[MTU] = {0};
	th->window = htons(LOCAL_WINDOW);
	th->crc = 0;

	psd_header psdHeader;
	psdHeader.saddr = ih->saddr;
	psdHeader.daddr = ih->daddr;
	psdHeader.mbz = 0;
	psdHeader.ptoto = IPPROTO_TCP;
	psdHeader.tcp_len = htons(tcp_len + data_len);

	memcpy(Buffer, &psdHeader, sizeof(psd_header));
	memcpy(Buffer + sizeof(psd_header), th, tcp_len + data_len);

	th->crc = CheckSum((u_short *)Buffer, tcp_len + sizeof(psd_header) + data_len);
}
int inline nxt_schedule_tcb()
{
	int tcb_it = -1;
	u_int tcb_index;

	u_long_long timeUsed;
	double timeInterval;
	double timeSleep;
	u_long_long current_time;

	while (!pool.ex_tcb.isEmpty())
	{
		tcb_it = pool.ex_tcb.iterator();
		tcb_index = pool.ex_tcb.state_id[tcb_it];
		current_time = timer.Start();
		//timeUsed = current_time - tcb_table[tcb_index]->startTime;

		tcb_bw_burst_ctrl(tcb_index, current_time, 0);
		timeUsed = tcb_table[tcb_index]->sliding_snd_window.timeInterval(current_time);
		if (tcb_table[tcb_index]->send_rate == 0 || tcb_table[tcb_index]->totalByteSent < MTU)
		{
			pool.ex_tcb.next();
			return tcb_it;
		}
		else
		{

			//timeInterval = (double)tcb_table[tcb_index]->totalByteSent * (double)RESOLUTION / (double)tcb_table[tcb_index]->send_rate;
			timeInterval = (double)tcb_table[tcb_index]->sliding_snd_window.bytes() * (double)RESOLUTION / (double)tcb_table[tcb_index]->send_rate;
			timeSleep = timeInterval - (double)timeUsed;

			if (timeSleep >= 1)
			{

				pool.ex_tcb.next();

				continue;
			}
			else
			{


				tcb_table[tcb_index]->startTime = timer.Start();
				tcb_table[tcb_index]->totalByteSent = 0;

				pool.ex_tcb.next();
				return tcb_it;
			}

		}
	}

	return -1;
}
int inline nxt_schedule_conn(u_int tcb_index)
{
	u_int it;

	if (!tcb_table[tcb_index]->states.isEmpty())
	{
		it = tcb_table[tcb_index]->states.iterator();
		tcb_table[tcb_index]->states.next();
		return it;
	}
	return -1;
}
void inline rm_tcb_conn(u_int tcb_index, u_short sport, int tcb_it, int conn_it)
{
	tcb_table[tcb_index]->states.del(conn_it);
	tcb_table[tcb_index]->conn[sport]->flush();

	pool._size --;
	conn_hash.size --;

	if (tcb_table[tcb_index]->states.isEmpty())
	{
		pool.ex_tcb.del(tcb_it);
		tcb_table[tcb_index]->flush();
		tcb_hash.size --;
	}
}
void* scheduler(void* _arg)
{
	struct pcap_pkthdr *header;

	DATA* data = (DATA *)_arg;
	Forward* forward = data->forward;

	ForwardPkt *tmpPkt, *timeoutPkt;
	u_short sport, tcb_index;
	u_long_long current_time;
	int tcb_it, conn_it;

	BOOL retransmit;
	BOOL newTransmit;

	u_int snd_win;
	int space;
	printf("State Ack iTime(ms) RTT(ms) SendRate(KB/s) TotalEstRate(KB/s) EstRate(KB/s) Conn\n");

	u_int seq_nxt = 0;

	while (TRUE)
	{
            pthread_mutex_lock(&pool.mutex);
            while (pool.ex_tcb.isEmpty())
                pthread_cond_wait(&pool.m_eventConnStateAvailable, &pool.mutex);

            pthread_mutex_unlock(&pool.mutex);

            tcb_it = nxt_schedule_tcb();

            if (tcb_it == -1)
                    continue;
            tcb_index = pool.ex_tcb.state_id[tcb_it];
            conn_it = nxt_schedule_conn(tcb_index);


            if (conn_it == -1)
                    continue;

            sport = tcb_table[tcb_index]->states.state_id[conn_it];

            if (sport == 0)
                    continue;

#ifdef DYNAMIC_RATE_FIT
            BW_adaptation(sport, tcb_index);
#endif

            pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
            if(tcb_table[tcb_index]->conn[sport]->server_state.state != CLOSED)
            {
                current_time = timer.Start();

#ifndef DEBUG
                printf("%d  %u  %u  %u  %u  %u  %u  %u  %u  %u  %hu  %u  %lu     \t\t\t\t\t\t\t\r", tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time/1000, tcb_table[tcb_index]->conn[sport]->RTT/1000, tcb_table[tcb_index]->conn[sport]->RTT_limit/1000, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->pkts_transit, sport, tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts(), tcb_table[tcb_index]->sliding_avg_window.size(), current_time);
#endif



#ifdef LOG_STAT
                log_data(sport, tcb_index);
#endif

                retransmit = TRUE;

                if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkts() > 0)
                {
                      /*
                    if (!tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                    {

                            snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);

                            __int64 space = snd_win - ((__int64)tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt - (__int64)tcb_table[tcb_index]->conn[sport]->server_state.snd_una);

                            tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                            if (tmpPkt->data_len > space)
                            {
                                    ReleaseMutex(tcb_table[tcb_index]->conn[sport]->mutex);

                                    continue;
                            }
                    }
                    */

                    if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
                    {
                        tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                        if (!tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                        {
                                snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                                space = snd_win - (int)(tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt - tcb_table[tcb_index]->conn[sport]->server_state.snd_una);
                                if ((int)tmpPkt->data_len > space + NUM_PKT_BEYOND_WIN * tcb_table[tcb_index]->conn[sport]->max_data_len)
                                {
                                    retransmit = FALSE;

                                    goto normal_timeout_check;
                                }
                        }
                        else if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                        {
                                 snd_win = tcb_table[tcb_index]->conn[sport]->max_data_len * BDP;
                                 space = snd_win - (int)tcb_table[tcb_index]->pkts_transit * (int)tcb_table[tcb_index]->conn[sport]->max_data_len;
                                 if ((int)tmpPkt->data_len > space)
                                 {
                                     retransmit = FALSE;

                                     goto normal_timeout_check;
                                 }
                        }

                        if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                tmpPkt->rtx_time = tmpPkt->snd_time;
                        tmpPkt->snd_time = 0;

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headNext();
                        if ((tmpPkt->ctr_flag & 0x01) == 1)
                        {
                                if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                                        tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                else
                                        tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                                if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;
                        }
                        else
                        {
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len;
                                if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;
                        }

normal_timeout_check:
                        timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                        if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto*2)
                        {
                                //if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, timeoutPkt->seq_num + timeoutPkt->data_len))
                                tcb_table[tcb_index]->conn[sport]->max_sack_edge = timeoutPkt->seq_num + timeoutPkt->data_len;

                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                tcb_table[tcb_index]->pkts_transit --;
                                tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                /*
                                u_int seq_num_head = tcb_table[tcb_index]->conn[sport]->server_state.snd_max;
                                u_int seq_num_una = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck()->seq_num;
                                tcb_table[tcb_index]->send_rate_upper = min(tcb_table[tcb_index]->send_rate_upper, (seq_num_head - seq_num_una) * 1000 / (current_time -  timeoutPkt->snd_time));
                                tcb_table[tcb_index]->send_rate = tcb_table[tcb_index]->send_rate_upper / 2;
                                tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno = max(seq_num_head, tcb_table[tcb_index]->conn[sport]->nxt_ack_seqno);
                                */

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                if (!timeoutPkt->rtx_time)
                                    timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                timeoutPkt->snd_time = 0;
                                /*
                                if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                        send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                */

#ifdef DEBUG
                                printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO TIMEOUT %u EXPIRED\n", timeoutPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rto);
#endif

                        }
                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
                    }
                    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                    {
                        tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                        if (MY_SEQ_GEQ(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge)) // Cannot retransmit beyong the largest right edge of SACK lists
                        {
                            retransmit = FALSE;
                            goto timeout_timer_check;
                        }

                        if (retransmit)
                        {
                            if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                    tmpPkt->rtx_time = tmpPkt->snd_time;
                            tmpPkt->snd_time = 0;
                        }

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headNext();

                        if ((tmpPkt->ctr_flag & 0x01) == 1)
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                                tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                            else
                                tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;

                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                        }
                        else
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num  + tmpPkt->data_len;

                        if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;

timeout_timer_check:
                        if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 0)
                        {
                            timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();

                            if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time  + tcb_table[tcb_index]->conn[sport]->rto)
                            {
                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                tcb_table[tcb_index]->conn[sport]->max_sack_edge = timeoutPkt->seq_num + timeoutPkt->data_len;
                                tcb_table[tcb_index]->pkts_transit --;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                if (!timeoutPkt->rtx_time)
                                     timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                timeoutPkt->snd_time = 0;

#ifdef DEBUG
                                printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO TIMEOUT %u EXPIRED\n", timeoutPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rto);
#endif

                                /*
                                if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                            send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                */

                            }
                        }
                        else if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1)
                        {
                            timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head);
                            if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                            {

                                tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                tcb_table[tcb_index]->pkts_transit --;
                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headPrev();
                                tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

                                if (!timeoutPkt->rtx_time)
                                     timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                timeoutPkt->snd_time = 0;

                                /*
                                if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                            send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                */

                            }
                        }


                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
                    }
                    else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
                    {
                        //tcb_bw_burst_ctrl(tcb_index, current_time);
                        newTransmit = FALSE;

                        tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                        if (MY_SEQ_LT(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
                        {

                        	/*
                            if (tcb_table[tcb_index]->conn[sport]->sack_block_num > 0)
                            {
                                    for (u_short i = 0; i < NUM_SACK_BLOCK; i ++)
                                    {
                                            if (tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block && tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block && MY_SEQ_GEQ(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->sack_block[i].left_edge_block) && MY_SEQ_LEQ(tmpPkt->seq_num + tmpPkt->data_len, tcb_table[tcb_index]->conn[sport]->sack_block[i].right_edge_block))
                                            {
                                                    retransmit = FALSE;
                                                    break;
                                            }
                                    }
                            }
                            */

                            if (!tmpPkt->is_rtx)
                                retransmit = FALSE;
                            else if (tmpPkt->is_rtx)
                            	tcb_table[tcb_index]->pkts_transit --;

                        }
                        else if (MY_SEQ_GEQ(tmpPkt->seq_num, tcb_table[tcb_index]->conn[sport]->max_sack_edge))
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win)
                            {
                                retransmit = FALSE;

                                /*
                                snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                                space = snd_win -(int)(tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->seq_num - tcb_table[tcb_index]->conn[sport]->server_state.snd_una);
                                if (space >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
                                    newTransmit = TRUE;
                                */

                                snd_win = tcb_table[tcb_index]->conn[sport]->max_data_len * BDP;
								space = snd_win - (int)tcb_table[tcb_index]->pkts_transit*(int)tcb_table[tcb_index]->conn[sport]->max_data_len;
								if (space >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
								{
									 newTransmit = TRUE;
								}


                                //newTransmit = TRUE;
                                goto fast_rtx_timer_check;

                            }
                            else
                            {
                                retransmit = FALSE;

                                snd_win = tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->server_state.win_scale);
                                space = snd_win - (int)(tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->seq_num - tcb_table[tcb_index]->conn[sport]->server_state.snd_una);
                                if (space  + NUM_PKT_BEYOND_WIN * tcb_table[tcb_index]->conn[sport]->max_data_len >= (int)tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead()->data_len)
                                    newTransmit = TRUE;

                                goto fast_rtx_timer_check;
                            }
                        }


                        if (retransmit)
                        {
                            if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                tmpPkt->rtx_time = tmpPkt->snd_time;
                            tmpPkt->snd_time = 0;
                        }

                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headNext();

                        if ((tmpPkt->ctr_flag & 0x01) == 1)
                        {
                            if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                                    tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                            else
                                    tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;

                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                        }
                        else
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num  + tmpPkt->data_len;

                        if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;

fast_rtx_timer_check:

                        timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();

                        if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                        {

                            tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;
                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;
                            if (!timeoutPkt->rtx_time)
                                timeoutPkt->rtx_time = timeoutPkt->snd_time;
                            timeoutPkt->snd_time = 0;

                            /*
                            if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                    send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                            */

#ifdef DEBUG
                            printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO TIMEOUT %u EXPIRED\n", timeoutPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rto);

#endif

                        }

                        if (newTransmit)
                        {

                            if (!tcb_table[tcb_index]->conn[sport]->send_out_awin && tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts > 0)
                            {
                                tmpPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHead();

                                if (tmpPkt->snd_time && !tmpPkt->rtx_time)
                                    tmpPkt->rtx_time = tmpPkt->snd_time;
                                tmpPkt->snd_time = 0;

                                tcb_table[tcb_index]->conn[sport]->dataPktBuffer.lastHeadNext();

                                if ((tmpPkt->ctr_flag & 0x01) == 1)
                                {
                                    if (tcb_table[tcb_index]->conn[sport]->server_state.state == SYN_REVD)
                                            tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                                    else
                                            tcb_table[tcb_index]->conn[sport]->server_state.state = FIN_WAIT_1;

                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num + tmpPkt->data_len + 1;
                                }
                                else
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tmpPkt->seq_num  + tmpPkt->data_len;

                                if (tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt > tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt;
                                retransmit = TRUE;
                            }
                        }
                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                    }

                    if (retransmit)
                    {

                        send_data_pkt(forward, tmpPkt);
                        tcb_table[tcb_index]->totalByteSent += tmpPkt->data_len;
                        tcb_table[tcb_index]->sliding_snd_window.put(tmpPkt->data_len, current_time, tmpPkt->seq_num);
                        tcb_table[tcb_index]->pkts_transit  ++;
                    }
                }
                else
                {
                    if (tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size > 0)
                    {

                        if (tcb_table[tcb_index]->conn[sport]->client_state.state == CLOSED && timeoutPkt->snd_time && current_time - timeoutPkt->snd_time > TIME_TO_LIVE)
                        {
                            tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
                            tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
#ifdef DEBUG
                                printf("CLIENT LEAVE ON CONNECTION %hu AFTER SEVERAL TIMEOUT\n", sport);
#endif
                        }
                        else
                        {
                            //init_retx_data_pkt(tcb_index, sport, tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size - tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts);

                            if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL)
                            {

                                timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                                if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto*2)
                                {
                                    tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                    tcb_table[tcb_index]->pkts_transit --;
                                    tcb_table[tcb_index]->conn[sport]->FRTO_ack_count = 0;
                                    tcb_table[tcb_index]->conn[sport]->FRTO_dup_ack_count = 0;

                                    //if (MY_SEQ_LT(tcb_table[tcb_index]->conn[sport]->max_sack_edge, timeoutPkt->seq_num + timeoutPkt->data_len))
                                    tcb_table[tcb_index]->conn[sport]->max_sack_edge = timeoutPkt->seq_num + timeoutPkt->data_len;

                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                    if (!timeoutPkt->rtx_time)
                                        timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                    timeoutPkt->snd_time = 0;

                                    /*
                                    if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                                send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                        */
                                }
                            }
                            else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
                            {

                                timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.unAck();
                                if (timeoutPkt->snd_time && current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                                {

                                    tcb_table[tcb_index]->conn[sport]->server_state.phase = FAST_RTX;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._head = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._unAck;
                                    tcb_table[tcb_index]->conn[sport]->dataPktBuffer._pkts = tcb_table[tcb_index]->conn[sport]->dataPktBuffer._size;
                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = timeoutPkt->seq_num;

                                    if (timeoutPkt->snd_time && !timeoutPkt->rtx_time)
                                        timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                    timeoutPkt->snd_time = 0;

                                    /*
                                    if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                            send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                    */
#ifdef DEBUG
                                        printf("LOCAL RETRANSMISSION PACKET %u ON CONNECTION %hu DUE TO TIMEOUT %u EXPIRED AT PHASE %d\n", timeoutPkt->seq_num, sport, tcb_table[tcb_index]->conn[sport]->rto, tcb_table[tcb_index]->conn[sport]->server_state.phase);
#endif
                                }

                            }
                            else if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL_TIMEOUT)
                            {

                                if (tcb_table[tcb_index]->conn[sport]->FRTO_ack_count == 1)
                                  {

                                    timeoutPkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.pkt(tcb_table[tcb_index]->conn[sport]->dataPktBuffer._last_head);
                                    if (timeoutPkt->snd_time)
                                    {
                                        if (current_time >= timeoutPkt->snd_time + tcb_table[tcb_index]->conn[sport]->rto)
                                        {

                                            tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                            tcb_table[tcb_index]->pkts_transit --;
                                            tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headPrev();
                                            tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head()->seq_num;

                                            if (!timeoutPkt->rtx_time)
                                                timeoutPkt->rtx_time = timeoutPkt->snd_time;
                                            timeoutPkt->snd_time = 0;

                                        /*
                                            if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd == 0)
                                                    send_ack_back(sport, data,  tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, tcb_table[tcb_index]->conn[sport]->sPort, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, 0 |16, 0, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);
                                             */
                                        }
                                    }
                                    else if (!timeoutPkt->snd_time)
                                    {
                                        tcb_table[tcb_index]->conn[sport]->server_state.phase = NORMAL_TIMEOUT;
                                        tcb_table[tcb_index]->conn[sport]->dataPktBuffer.headPrev();
                                        ForwardPkt *this_pkt = tcb_table[tcb_index]->conn[sport]->dataPktBuffer.head();

                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = this_pkt->seq_num;

                                        if (!this_pkt->rtx_time)
                                             this_pkt->rtx_time = this_pkt->snd_time;
                                        this_pkt->snd_time = 0;

                                    }

                                }
                            }
                        }
                    }

                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                }
            }
            else if (tcb_table[tcb_index]->conn[sport]->server_state.state == CLOSED && tcb_table[tcb_index]->conn[sport]->client_state.state == CLOSED)
            {
                pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                pthread_mutex_lock(&tcb_table[tcb_index]->mutex);
                rm_tcb_conn(tcb_index, sport, tcb_it, conn_it);
                pthread_mutex_unlock(&tcb_table[tcb_index]->mutex);

            }
            else
            {
                pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
            }

	}

}
void* forwarder(void* arg)
{
	Forward* forward = (Forward* )arg;
	struct pcap_pkthdr header;
	u_char pkt_data[PKT_SIZE];

	u_short dport, sport;
	u_int index, tcb_index;
	u_short data_len;

	while(1)
	{

            pthread_mutex_lock(&forward->mutex);
            while (forward->pktQueue.size() == 0)
                pthread_cond_wait(&forward->m_eventElementAvailable, &forward->mutex);

            ForwardPkt* tmpForwardPkt = forward->pktQueue.head();
            dport = tmpForwardPkt->dPort;
            index = tmpForwardPkt->index;
            sport = tmpForwardPkt->sPort;
            data_len = tmpForwardPkt->data_len;
            tcb_index = tmpForwardPkt->tcb;
            memcpy(&header, &(tmpForwardPkt->header), sizeof(struct pcap_pkthdr));
            memcpy(pkt_data, tmpForwardPkt->pkt_data, header.len);
            tmpForwardPkt->initPkt();
            forward->pktQueue.headNext();
            forward->pktQueue.decrease();
            pthread_cond_signal(&forward->m_eventSpaceAvailable);
            pthread_mutex_unlock(&forward->mutex);

            if (pcap_sendpacket(forward->dev, pkt_data, header.len) != 0)
            {
                fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(forward->dev));
                exit(-1);
            }

            if(sport == APP_PORT_NUM)
            {

                //pthread_mutex_lock(&tcb_table[tcb_index]->mutex);
                if (tcb_table[tcb_index]->conn[dport] && tcb_table[tcb_index]->conn[dport]->server_state.state != CLOSED)
                {
                    ForwardPkt* sendPkt = tcb_table[tcb_index]->conn[dport]->dataPktBuffer.pkt(index);
                    sendPkt->snd_time = timer.Start();
                    //tcb_table[tcb_index]->pkts_transit ++;
                }
                //pthread_mutex_unlock(&tcb_table[tcb_index]->mutex);

            }

	}
}
void* capturer(void* _data)
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	DATA* data = (DATA *)_data;
	int res;
	u_char pkt_buffer[MTU];
	srand(time(NULL));

	u_long_long current_time;
	char key[sizeof(ip_address)+sizeof(u_short)];

	while((res = pcap_next_ex(data->dev_this, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		  continue; // Timeout elapsed

		current_time = timer.Start();
		if (pkt_data[14] == '\0')
			send_forward(data, header, pkt_data);
		else if (pkt_data[14] != '\0')
		{
			mac_header* mh = (mac_header *)pkt_data; // mac header
			ip_header* ih = (ip_header *) (pkt_data + 14); //length of ethernet header
			u_int ip_len = (ih->ver_ihl & 0xf) * 4;
			u_short total_len = ntohs(ih->tlen);
			u_short id = ntohs(ih->identification);

			if ((u_int)ih->proto != 6)
				send_forward(data, header, pkt_data);
			else if ((u_int)ih->proto == 6) //TCP
			{
				tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
				u_short sport = ntohs(th->sport);
				u_short dport = ntohs(th->dport);
				u_int seq_num = ntohl(th->seq_num);
				u_int ack_num = ntohl(th->ack_num);
				u_short window = ntohs(th->window);
				u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
				u_short ctr_flag = ntohs(th->hdr_len_resv_code)&0x003f;
				u_short data_len = total_len - ip_len - tcp_len;


				if (sport == APP_PORT_NUM) //coming from server and we have already allocated a connection table
				{
					int tcb_index = tcb_hash.search((char *)&ih->daddr, sizeof(ip_address), &ih->daddr);
					if (tcb_index == -1)
					{
#ifdef DEBUG
						printf("CANNOT FIND A TCB FOR USER %d.%d.%d.%d PORT %hu\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);

#endif
						continue;
					}

					if (!tcb_table[tcb_index]->conn[dport])
					{
#ifdef DEBUG
						printf("CAN FIND A TCB FOR USER %c.%c.%c.%c BUT NO CONNECTION FOR PORT %hu\n", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4, dport);

#endif
						continue;
					}
					else if (tcb_table[tcb_index]->conn[dport] != NULL)
					{
						tcb_table[tcb_index]->conn[dport]->client_state.snd_nxt = ack_num;
						switch(tcb_table[tcb_index]->conn[dport]->client_state.state)
						{
							case SYN_SENT:
							if (ctr_flag == 18) //SYN+ACK pkt
							{
                                                            u_short flag = 0;
                                                            if (tcp_len > 20) // TCP Options
                                                            {
                                                                u_int tcp_opt_len = tcp_len - 20;
                                                                u_char *tcp_opt = (u_char *)th + 20;
                                                                syn_sack_option(tcp_opt, tcp_opt_len, dport, FALSE, tcb_index);
                                                                rcv_header_update(ih, th, tcp_len, data_len);
                                                                /*
                                                                th->window = htons(LOCAL_WINDOW);
                                                                th->crc = 0;

                                                                memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                                                psd_header psdHeader;

                                                                psdHeader.saddr = ih->saddr;
                                                                psdHeader.daddr = ih->daddr;
                                                                psdHeader.mbz = 0;
                                                                psdHeader.ptoto = IPPROTO_TCP;
                                                                psdHeader.tcp_len = htons(tcp_len);

                                                                memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                                                memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len);
                                                                th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header));
                                                                */
                                                            }

                                                            tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = seq_num + 1;
                                                            tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                            tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd;

#ifdef COMPLETE_SPLITTING_TCP
                                                            //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                            u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                            send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                            ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[dport]->client_state.httpRequest;
                                                            if (tmpForwardPkt->occupy)
                                                            {
                                                                    ip_header* ih = (ip_header *)((u_char *)tmpForwardPkt->pkt_data + 14);
                                                                    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
                                                                    u_short total_len = ntohs(ih->tlen);
                                                                    tcp_header* th = (tcp_header *)((u_char *)ih + ip_len);
                                                                    u_short tcp_len = ((ntohs(th->hdr_len_resv_code)&0xf000)>>12)*4;
                                                                    u_short data_len = total_len - ip_len - tcp_len;
                                                                    th->ack_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt);
                                                                    th->window = htons(adv_win);
                                                                    rcv_header_update(ih, th, tcp_len, data_len);

                                                                    send_backward(data, &tmpForwardPkt->header, tmpForwardPkt->pkt_data);
                                                                    tmpForwardPkt->initPkt();
                                                            }
#else
                                                            tcb_table[tcb_index]->conn[dport]->server_state.state = SYN_REVD;
                                                            tcb_table[tcb_index]->conn[dport]->server_state.snd_una = seq_num;
                                                            tcb_table[tcb_index]->conn[dport]->server_state.seq_nxt = seq_num + 1;
                                                            tcb_table[tcb_index]->conn[dport]->server_state.snd_nxt = seq_num + 1;
                                                            tcb_table[tcb_index]->conn[dport]->server_state.snd_max = seq_num + 1;
                                                            send_forward(data, header, pkt_data);
#endif
                                                            //tcb_table[tcb_index]->conn[dport]->client_state.state = ESTABLISHED;
							}
							else
							{
#ifdef DEBUG
								printf("SYN+ACK PACKET IS REQUIRED TO INIT CONNECTION %hu\n", dport);
#endif
							}
							break;

							case ESTABLISHED:
							if ((ctr_flag & 0x10) == 16 && seq_num < tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
							{
								u_short flag = 0;
#ifdef DEBUG
								printf("RECEIVING OLD PACKET %u WAITING PACKET %u ON CONNECTION %hu\n", seq_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, dport);
#endif

								//tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
								tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;
								//u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
								//u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
								u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

								if (adv_win && adv_win != LOCAL_WINDOW)
									adv_win ++;

								if (adv_win)
								{
									send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

								}
								else if (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
								{
									send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

									tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
								}

								if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
									tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
							}
							else if ((ctr_flag & 0x10) == 16 && seq_num >= tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt) /*&& seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt < (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS*/ // have ACK flag
							{
							    if (data_len > 0 || (ctr_flag & 0x01) == 1)
							    {
							        u_short flag = 0;
								u_short adv = 0;

								if (seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt < (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS)
								{
								    if (seq_num == tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                                                    {
#ifdef COMPLETE_SPLITTING_TCP
                                                                            th->seq_num = htonl(tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt);
                                                                            rcv_header_update(ih, th, tcp_len, data_len);

                                                                            /*
                                                                            th->crc = 0;
                                                                            memset(pkt_buffer, 0, sizeof(pkt_buffer));
                                                                            psd_header psdHeader;
                                                                            psdHeader.saddr = ih->saddr;
                                                                            psdHeader.daddr = ih->daddr;
                                                                            psdHeader.mbz = 0;
                                                                            psdHeader.ptoto = IPPROTO_TCP;
                                                                            psdHeader.tcp_len = htons(tcp_len + data_len);

                                                                            memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
                                                                            memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);
                                                                            th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);
                                                                            */
#endif
                                                                            if ((ctr_flag & 0x01) == 1)
                                                                            {
											
                                                                                    pthread_mutex_lock(&tcb_table[tcb_index]->conn[dport]->mutex);
										    rcv_data_pkt(data, header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);
										    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[dport]->mutex);

                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt += (data_len + 1);
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = check_sack_list(tcb_index, dport, seq_num, data_len) + 1;
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd;
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;
                                                                                    //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                                                    //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv5_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                                                    u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                                                    if (adv_win && adv_win != LOCAL_WINDOW)
                                                                                            adv_win ++;

                                                                                    send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.state = CLOSE_WAIT;
                                                                                    send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16|1, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.state = LAST_ACK;
                                                                            }
                                                                            else if (data_len > 0)
                                                                            {
										    pthread_mutex_lock(&tcb_table[tcb_index]->conn[dport]->mutex);
                                                                                    rcv_data_pkt(data, header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);
                                                                                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[dport]->mutex);

                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.seq_nxt += data_len;
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = check_sack_list(tcb_index, dport, seq_num, data_len);
                                                                                    //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;
                                                                                    adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd - (tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt);
                                                                                    //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 1) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                                                    //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                                                    //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                                                    u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                                                    if (adv_win && adv_win != LOCAL_WINDOW)
                                                                                            adv_win ++;
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd;

                                                                                    BOOL acking = FALSE;
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.ack_count = tcb_table[tcb_index]->conn[dport]->client_state.ack_count + 1;
                                                                                    if ((tcb_table[tcb_index]->conn[dport]->client_state.ack_count = tcb_table[tcb_index]->conn[dport]->client_state.ack_count % 2) == 0)
                                                                                            acking = TRUE;

                                                                                    if (acking == TRUE || (ctr_flag & 0x08) == 8)
                                                                                    {
                                                                                            if (adv_win || (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt))
                                                                                            {
                                                                                                    send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                                                                    if (!adv_win)
                                                                                                            tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                                                                            }

                                                                                            if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                                                                            else
                                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 0;
                                                                                    }
                                                                            }

                                                                    }
                                                                    else // out of order packets
                                                                    {
#ifdef DEBUG
                                                                            printf("DISCARD OUT OF ORDER PACKET %u WAITTING ON PACKET %u ON CONNECTION %hu---\n", seq_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, dport);

#endif
									    pthread_mutex_lock(&tcb_table[tcb_index]->conn[dport]->mutex);
                                                                            rcv_data_pkt(data, header, pkt_data, sport, dport, seq_num, data_len, ctr_flag, tcb_index);
                                                                            pthread_mutex_unlock(&tcb_table[tcb_index]->conn[dport]->mutex);
                                                                            printf("seq no: %u data_len: %u ack no: %u rcv_nxt: %u size: %u\n", seq_num, data_len, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size());

                                                                            create_sack_list(tcb_index, dport, seq_num, data_len);

                                                                            tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[dport]->MSS;

                                                                            //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
                                                                            //tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 1) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                                            //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                                            //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                                            u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                                            if (adv_win && adv_win != LOCAL_WINDOW)
                                                                                    adv_win ++;

                                                                            if (adv_win)
                                                                            {
                                                                                    send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                                            }
                                                                            else if (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                                                            {
                                                                                    send_ack_back(dport, data, tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);
                                                                                    tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                                                            }

                                                                            if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                                                    tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                                                    }
								}
								else if (/*(ctr_flag & 0x10) == 16 && (data_len > 0 || (ctr_flag & 0x01) == 1) &&*/seq_num - tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt >= (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS) // Outbound packets
                                                                {
                                                                        //u_short flag = 0;
								        tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;

#ifdef DEBUG
                                                                        printf("DISCARD OUT OF WINDOW PACKET %u WINDOW SIZE %u WAITTING ON PACKET %u %u ON CONNECTION %hu\n", seq_num, tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size(), tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, tcb_table[tcb_index]->conn[dport]->MSS, dport);
#endif
                                                                       // tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() > 2 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[dport]->MSS:0);
                                                                        //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                                        //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));

                                                                        u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                                        if (adv_win && adv_win != LOCAL_WINDOW)
                                                                                adv_win ++;

                                                                        if (adv_win)
                                                                        {
                                                                                send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                                        }
                                                                        else if (!adv_win && tcb_table[tcb_index]->conn[dport]->zero_window_seq_no != tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt)
                                                                        {
                                                                                send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);

                                                                                tcb_table[tcb_index]->conn[dport]->zero_window_seq_no = tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt;
                                                                        }

                                                                        if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[dport]->MSS)
                                                                                tcb_table[tcb_index]->conn[dport]->client_state.ack_count = 1; // next ready to ack
                                                                }
							    }
							    else
							    {
							         send_forward(data, header, pkt_data);
							    }

							}
							break;

							case FIN_WAIT_1:
							if ((ctr_flag & 0x10) == 16)
							{
                                                            if ((ctr_flag & 0x01) == 1)
                                                            {
                                                                u_short flag = 0;
                                                                tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[dport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[dport]->MSS;
                                                                //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd);
                                                                //u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                                u_short adv_win = (tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[dport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[dport]->client_state.win_scale));
                                                                if (adv_win && adv_win != LOCAL_WINDOW)
                                                                        adv_win ++;

                                                                tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt = check_sack_list(tcb_index, dport, seq_num, data_len) + 1;
                                                                send_ack_back(dport, data,  tcb_table[tcb_index]->conn[dport]->client_ip_address, tcb_table[tcb_index]->conn[dport]->server_ip_address, tcb_table[tcb_index]->conn[dport]->client_mac_address, tcb_table[tcb_index]->conn[dport]->server_mac_address, dport, sport, ack_num, seq_num + data_len + 1, flag|16, adv_win, tcb_table[tcb_index]->conn[dport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[dport]->client_state.sack);


                                                                tcb_table[tcb_index]->conn[dport]->client_state.state = CLOSED;
#ifdef DEBUG
                                                                    printf("CONNECTION CLOSED INITIATED BY CLIENT SIDE ON CONNECTION %hu\n", dport);
                                                                    printf("CLOSED GATEWAY-SERVER CONNECTION %hu\n", dport);
#endif
                                                            }
							}
							break;

							case LAST_ACK:
							if ((ctr_flag & 0x10) == 16 /*&& seq_num == tcb_table[tcb_index]->conn[dport]->client_state.rcv_nxt*/)
							{
								tcb_table[tcb_index]->conn[dport]->client_state.state = CLOSED;
#ifdef DEBUG
								printf("CLOSED GATEWAY-SERVER CONNECTION %hu\n", dport);
#endif
							}
							break;
						}
					}
				}
				else if (dport == APP_PORT_NUM) //coming from client
				{
					int tcb_index = tcb_hash.search((char *)&ih->saddr, sizeof(ip_address), &ih->saddr);

					if (tcb_index != -1 && tcb_table[tcb_index]->conn[sport] != NULL)
					{

						if ((ctr_flag & 0x04) == 4)//RST
						{
							/*
							pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
							delete tcb_table[tcb_index]->conn[sport];
							tcb_table[tcb_index]->conn[sport] = NULL;
							pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
							*/

#ifdef COMPLETE_SPLITTING_TCP

							th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
							rcv_header_update(ih, th, tcp_len, data_len);

							/*
							th->window = htons(LOCAL_WINDOW);
							th->crc = 0;

							memset(pkt_buffer, 0, sizeof(pkt_buffer));
							psd_header psdHeader;

							psdHeader.saddr = ih->saddr;
							psdHeader.daddr = ih->daddr;
							psdHeader.mbz = 0;
							psdHeader.ptoto = IPPROTO_TCP;
							psdHeader.tcp_len = htons(tcp_len + data_len);

							memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
							memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len + data_len);
							th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header) + data_len);
							*/

#endif
							send_forward(data, header, pkt_data);
#ifdef DEBUG
							printf("CLOSED GATEWAY-SERVER CONNECTION %hu\n", sport);
							printf("CLOSED GATEWAY-CLIENT CONNECTION %hu\n", sport);
#endif
							if (tcb_table[tcb_index]->conn[sport] != NULL)
							{
								tcb_table[tcb_index]->conn[sport]->client_state.state = CLOSED;
								tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
							}

							continue;
						}

						switch(tcb_table[tcb_index]->conn[sport]->server_state.state)
						{
							case SYN_REVD:
							if ((ctr_flag & 0x10) == 16 && ack_num > tcb_table[tcb_index]->conn[sport]->server_state.snd_una && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max) //ACK
							{

								tcb_table[tcb_index]->conn[sport]->server_state.state = ESTABLISHED;
								tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

#ifdef COMPLETE_SPLITTING_TCP
								tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;
								if (data_len > 0) //http request
								{
									ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[sport]->client_state.httpRequest;
									tmpForwardPkt->data = (void *)data;
									memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
									memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
									memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
									tmpForwardPkt->sPort = sport;
									tmpForwardPkt->dPort = dport;
									tmpForwardPkt->seq_num = seq_num;
									tmpForwardPkt->data_len = data_len;
									tmpForwardPkt->ctr_flag = ctr_flag;
									tmpForwardPkt->snd_time = 0;
									tmpForwardPkt->rcv_time = 0;
									tmpForwardPkt->num_dup = 0;
									tmpForwardPkt->RTT = 0;
									tmpForwardPkt->occupy = true;

									if (tcb_table[tcb_index]->conn[sport]->client_state.state == ESTABLISHED)
									{
										th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
										th->window = htons(LOCAL_WINDOW);
										rcv_header_update(ih, th, tcp_len, data_len);

										tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;

										memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
										memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);

										send_forward(data, header, pkt_data);
										tmpForwardPkt->initPkt();
									}
								}
#endif

#ifndef COMPLETE_SPLITTING_TCP
								tcb_table[tcb_index]->conn[sport]->client_state.state = ESTABLISHED;

								//send_forward(data, header, pkt_data);
								send_wait_forward(data, header, pkt_data); // test with wifi
#endif
							}
							else if (ctr_flag == 2) //SYN pkt retransmission
							{
								assert(tcp_len > 20); // SYN must have TCP Options
								u_short flag = 0;

								u_int tcp_opt_len = tcp_len - 20;
								u_char *tcp_opt = (u_char *)th + 20;
								syn_sack_option(tcp_opt, tcp_opt_len, sport, TRUE, tcb_index);
								rcv_header_update(ih, th, tcp_len, data_len);
								/*
								th->window = htons(LOCAL_WINDOW);
								th->crc = 0;

								memset(pkt_buffer, 0, sizeof(pkt_buffer));
								psd_header psdHeader;

								psdHeader.saddr = ih->saddr;
								psdHeader.daddr = ih->daddr;
								psdHeader.mbz = 0;
								psdHeader.ptoto = IPPROTO_TCP;
								psdHeader.tcp_len = htons(tcp_len);

								memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
								memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len);
								th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header));
								*/
								tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = CIRCULAR_BUF_SIZE * tcb_table[tcb_index]->conn[sport]->MSS; // can be increased
								tcb_table[tcb_index]->conn[sport]->client_state.state = SYN_SENT;
								tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;

#ifdef COMPLETE_SPLITTING_TCP
								tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
								tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
								tcb_table[tcb_index]->conn[sport]->server_state.snd_una = tcb_table[tcb_index]->conn[sport]->server_state.snd_una;
								tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
								tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
								tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
#endif
								send_forward(data, header, pkt_data);
#ifdef COMPLETE_SPLITTING_TCP
								send_syn_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, seq_num + data_len + 1, flag|18, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, tcp_opt, tcp_opt_len, pkt_buffer);
#endif
							}
							else
							{
#ifdef DEBUG
								printf("FLAG %hu UNACK PACKET DUMPED IN SYN_REV STATE\n", ctr_flag);
#endif
							}
							break;

							case ESTABLISHED:
							if ((ctr_flag & 0x10) == 16) // have ACK flag
							{
								tcb_table[tcb_index]->conn[sport]->server_state.state = ESTABLISHED;

								/*
								if (tcp_len > 20) // TCP Options
								{
									u_int tcp_opt_len = tcp_len - 20;
									u_char *tcp_opt = (u_char *)th + 20;
									ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index);
								}
								else
								{
									if (tcb_table[tcb_index]->conn[sport]->sack_block_num > 0)
									{
										clean_sack(sport, ack_num, tcb_index);
									}
								}
                                                                */

								if ((ctr_flag & 0x01) == 1) //FIN Received
								{
									u_short flag = 0;
                                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
                                                                        tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;

                                                                        pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

									send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, seq_num + data_len + 1, flag|16|1, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

									tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt ++;
									tcb_table[tcb_index]->conn[sport]->server_state.snd_max ++;

									/*
									send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, seq_num + data_len + 1, flag|16|1, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1);
									*/

									if (tcb_table[tcb_index]->conn[sport]->client_state.state != CLOSED)
									{
#ifdef COMPLETE_SPLITTING_TCP
                                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                                            rcv_header_update(ih, th, tcp_len, data_len);
#endif
                                                                            tcb_table[tcb_index]->conn[sport]->client_state.state = FIN_WAIT_1;
                                                                            send_forward(data, header, pkt_data);
									}

									tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
#ifdef DEBUG
									printf("CLOSED GATEWAY-CLIENT CONNECTION %hu\n", sport);
#endif
								}
								else if (data_len > 0 && MY_SEQ_GEQ(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max) // data packet needs be acked
								{
									tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
									tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;

									pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                                        rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                                        pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

#ifdef COMPLETE_SPLITTING_TCP
									ForwardPkt* tmpForwardPkt = tcb_table[tcb_index]->conn[sport]->client_state.httpRequest;
									tmpForwardPkt->data = (void *)data;
									memcpy(&(tmpForwardPkt->header), header, sizeof(struct pcap_pkthdr));
									memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
									memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);
									tmpForwardPkt->sPort = sport;
									tmpForwardPkt->dPort = dport;
									tmpForwardPkt->seq_num = seq_num;
									tmpForwardPkt->data_len = data_len;
									tmpForwardPkt->ctr_flag = ctr_flag;
									tmpForwardPkt->snd_time = 0;
									tmpForwardPkt->rcv_time = 0;
									tmpForwardPkt->num_dup = 0;
									tmpForwardPkt->RTT = 0;
									tmpForwardPkt->occupy = true;

									tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = ack_num;

									if (tcb_table[tcb_index]->conn[sport]->client_state.state == ESTABLISHED)
									{
										th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
										th->window = htons(LOCAL_WINDOW);
										rcv_header_update(ih, th, tcp_len, data_len);

										tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
										memset(tmpForwardPkt->pkt_data, 0, sizeof(tmpForwardPkt->pkt_data));
										memcpy(tmpForwardPkt->pkt_data, pkt_data, header->len);

										send_forward(data, header, pkt_data);
										tmpForwardPkt->initPkt();
									}
#else
									send_forward(data, header, pkt_data);
#endif
									//u_short flag = 0;
									//send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, ack_num, seq_num + data_len, flag|16, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

									// Initialize the parameters for rate control algorithm
									//tcb_table[tcb_index]->conn[sport]->reset_timer = TRUE;


								}
								else if (MY_SEQ_GT(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
								{
									pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
									rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
									pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

									u_int adv_win = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
									if (adv_win >= tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd + 0.5 * tcb_table[tcb_index]->conn[sport]->dataPktBuffer.capacity * tcb_table[tcb_index]->conn[sport]->MSS || !tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd)
									{
										u_short flag = 0;
										//tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2 > 0 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[sport]->MSS:0);
										tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[sport]->MSS;
										tcb_table[tcb_index]->conn[sport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd;
										//u_short adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
										u_short adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
										if (adv_win && adv_win != LOCAL_WINDOW)
											adv_win ++;

										if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd >= tcb_table[tcb_index]->conn[sport]->MSS)
											send_win_update_forward(sport, data, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, dport, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

										if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[sport]->MSS)
											tcb_table[tcb_index]->conn[sport]->client_state.ack_count = 1; // next ready to ack
									}

								}
								else if (ack_num == tcb_table[tcb_index]->conn[sport]->server_state.snd_una)
								{
									pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);

									rcv_dup_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
									pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
								}
								else
								{
#ifdef DEBUG
									printf("FLAGS %hu PACKET DUMPED\n", ctr_flag);
#endif
								}
							}
							else
							{
#ifdef DEBUG
								printf("FLAG %hu UNACK PACKET DUMPED IN ESTABLISH STATE\n", ctr_flag);
#endif
							}
							break;

							case FIN_WAIT_1:
							if ((ctr_flag & 0x10) == 16)
							{
								/*
							        if (tcp_len > 20) // TCP Options
								{
									u_int tcp_opt_len = tcp_len - 20;
									u_char *tcp_opt = (u_char *)th + 20;
									ack_sack_option(tcp_opt, tcp_opt_len, sport, ack_num, tcb_index);
								}
                                                                */

								if ((ctr_flag & 0x01) == 1) //FIN Received
								{
                                                                    u_short flag = 0;

                                                                    send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, seq_num + data_len + 1, flag|16, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt ++;
                                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_max ++;
                                                                    /*
                                                                    send_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt, seq_num + data_len + 1, flag|16|1, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1);
                                                                    */
                                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_una = ack_num;
                                                                    tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;

                                                                    pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                                    rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                                                                    if (tcb_table[tcb_index]->conn[sport]->client_state.state != CLOSED)
                                                                    {
#ifdef COMPLETE_SPLITTING_TCP
                                                                            th->ack_num = htonl(tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt);
                                                                            rcv_header_update(ih, th, tcp_len, data_len);
#endif
                                                                        tcb_table[tcb_index]->conn[sport]->client_state.state = FIN_WAIT_1;
                                                                        send_forward(data, header, pkt_data);
                                                                    }
                                                                    tcb_table[tcb_index]->conn[sport]->server_state.state = CLOSED;
#ifdef DEBUG
									printf("CLOSED GATEWAY-CLIENT CONNECTION %hu\n", sport);
#endif
								}
								else if (MY_SEQ_GT(ack_num, tcb_table[tcb_index]->conn[sport]->server_state.snd_una) && ack_num <= tcb_table[tcb_index]->conn[sport]->server_state.snd_max)
								{
                                                                    pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                                    rcv_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);

                                                                    u_int adv_win = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size()) * tcb_table[tcb_index]->conn[sport]->MSS;
                                                                    if (adv_win >= tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd + 0.5 * tcb_table[tcb_index]->conn[sport]->dataPktBuffer.capacity * tcb_table[tcb_index]->conn[sport]->MSS || !tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd)
                                                                    {
                                                                        u_short flag = 0;
                                                                        //tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2 > 0 ? (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size() - 2) * tcb_table[tcb_index]->conn[sport]->MSS:0);
                                                                        tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())*tcb_table[tcb_index]->conn[sport]->MSS;
                                                                        tcb_table[tcb_index]->conn[sport]->client_state.rcv_adv = tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt + tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd;
                                                                        //u_short adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd > LOCAL_WINDOW * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
                                                                        adv_win = (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) > LOCAL_WINDOW ? LOCAL_WINDOW : tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd / pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale));
                                                                        if (adv_win && adv_win != LOCAL_WINDOW)
                                                                                adv_win ++;

                                                                        if (tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd >= tcb_table[tcb_index]->conn[sport]->MSS)
                                                                            send_win_update_forward(sport, data, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, sport, dport, tcb_table[tcb_index]->conn[sport]->client_state.snd_nxt, tcb_table[tcb_index]->conn[sport]->client_state.rcv_nxt, flag|16, adv_win, tcb_table[tcb_index]->conn[sport]->client_state.send_data_id + 1, &tcb_table[tcb_index]->conn[sport]->client_state.sack);

                                                                        if (adv_win * pow((float)2, (int)tcb_table[tcb_index]->conn[sport]->client_state.win_scale) < 2 * tcb_table[tcb_index]->conn[sport]->MSS)
                                                                                tcb_table[tcb_index]->conn[sport]->client_state.ack_count = 1; // next ready to ack
                                                                    }
								}
								else if (ack_num == tcb_table[tcb_index]->conn[sport]->server_state.snd_una)
								{
                                                                    pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
                                                                    rcv_dup_ack_handler((u_char *)th, tcp_len, ack_num, window, sport, tcb_index, current_time);
                                                                    pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
								}
								else
								{
#ifdef DEBUG
									printf("FLAGS %hu PACKET DUMPED\n", ctr_flag);
#endif
								}
							}
							else
							{
#ifdef DEBUG
								printf("FLAG %hu UNACK PACKET DUMPED IN FIN_WAIT STATE\n", ctr_flag);
#endif
							}
							break;

							case CLOSED:
							break;
						}
					}
					else //tcb exists but conn does not exist, or tcb does not exist and conn does not exists
					{
						if (ctr_flag == 2)  //SYN packet
						{
							if (tcb_index == -1)
							{
								tcb_index = tcb_hash.Hash((char *)&ih->saddr, sizeof(ip_address));

								tcb_table[tcb_index]->init_tcb(ih->saddr, ih->daddr);
								pool.add_tcb(tcb_index);
							}

							memcpy(key, &ih->saddr, sizeof(ip_address));
							memcpy(key+sizeof(ip_address), &sport, sizeof(u_short));
							int conn_index = conn_hash.Hash(key, sizeof(key));
							if (conn_index == -1)
								continue;

							conn_table[conn_index]->init_state_ex(mh->mac_src, mh->mac_dst, ih->saddr, ih->daddr, sport, dport, tcb_table[tcb_index]);
							tcb_table[tcb_index]->add_conn(sport, conn_table[conn_index]);
							pool._size ++;

							//assert(tcp_len > 20); // SYN must have TCP Options
							u_short flag = 0;
							u_int tcp_opt_len = tcp_len - 20;
							u_char *tcp_opt = (u_char *)th + 20;
							syn_sack_option(tcp_opt, tcp_opt_len, sport, TRUE, tcb_index);
							rcv_header_update(ih, th, tcp_len, data_len);

							/*
							th->window = htons(LOCAL_WINDOW);
							th->crc = 0;
							memset(pkt_buffer, 0, sizeof(pkt_buffer));
							psd_header psdHeader;

							psdHeader.saddr = ih->saddr;
							psdHeader.daddr = ih->daddr;
							psdHeader.mbz = 0;
							psdHeader.ptoto = IPPROTO_TCP;
							psdHeader.tcp_len = htons(tcp_len);

							memcpy(pkt_buffer, &psdHeader, sizeof(psd_header));
							memcpy(pkt_buffer + sizeof(psd_header), th, tcp_len);
							th->crc = CheckSum((u_short *)pkt_buffer, tcp_len + sizeof(psd_header));
							*/

							tcb_table[tcb_index]->conn[sport]->client_state.state = SYN_SENT;
							tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
							tcb_table[tcb_index]->conn[sport]->client_state.rcv_wnd = (CIRCULAR_BUF_SIZE - tcb_table[tcb_index]->conn[sport]->dataPktBuffer.size())* tcb_table[tcb_index]->conn[sport]->MSS; // can be increased

							if (tcb_table[tcb_index]->send_beyong_win)
							    tcb_table[tcb_index]->conn[sport]->server_state.ignore_adv_win = TRUE;

#ifdef COMPLETE_SPLITTING_TCP
							tcb_table[tcb_index]->conn[sport]->server_state.state = SYN_REVD;
							tcb_table[tcb_index]->conn[sport]->server_state.snd_wnd = window;
							tcb_table[tcb_index]->conn[sport]->server_state.snd_una = rand()%900000 + 100000;
							tcb_table[tcb_index]->conn[sport]->client_state.seq_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;;

							tcb_table[tcb_index]->conn[sport]->server_state.snd_nxt = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;
							tcb_table[tcb_index]->conn[sport]->server_state.snd_max = tcb_table[tcb_index]->conn[sport]->server_state.snd_una + 1;

							send_syn_ack_back(sport, data, tcb_table[tcb_index]->conn[sport]->server_ip_address, tcb_table[tcb_index]->conn[sport]->client_ip_address, tcb_table[tcb_index]->conn[sport]->server_mac_address, tcb_table[tcb_index]->conn[sport]->client_mac_address, dport, sport, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, seq_num + data_len + 1, flag|18, 6400, tcb_table[tcb_index]->conn[sport]->server_state.send_data_id + 1, tcp_opt, tcp_opt_len, pkt_buffer);
#endif


							send_forward(data, header, pkt_data);
							//send_wait_forward(data, header, pkt_data);
						}
						else
						{
#ifdef DEBUG
							printf("SYN IS REQUIRED TO CREATE A TCB\n");
#endif
						}
					}
				}
				else
				        send_forward(data, header, pkt_data);
			}
		}
	}

	if (res < 0)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(data->dev_this));
		exit(-1);
	}

}
void* monitor(void* dummy)
{
#ifdef BW_SMOOTH
	u_short sport;
	int tcb_it, conn_it;
	u_int tcb_index;
	u_long_long current_time;





	printf("State Ack iTime(ms) RTT(ms) SendRate(KB/s) TotalEstRate(KB/s) EstRate(KB/s) Conn\n");

	while(TRUE)
	{
		pthread_mutex_lock(&pool.mutex);
		while (pool.ex_tcb.isEmpty())
			pthread_cond_wait(&pool.m_eventConnStateAvailable, &pool.mutex);

		tcb_it = pool.ex_tcb.iterator();
		tcb_index = pool.ex_tcb.state_id[tcb_it];

		pthread_mutex_unlock(&pool.mutex);


		pthread_mutex_lock(&tcb_table[tcb_index]->mutex);
		if (!tcb_table[tcb_index]->states.isEmpty())
		{
			conn_it = tcb_table[tcb_index]->states.iterator();
			sport = tcb_table[tcb_index]->states.state_id[conn_it];
		}
		else
		{
			pthread_mutex_unlock(&tcb_table[tcb_index]->mutex);
			continue;
		}

		pthread_mutex_lock(&tcb_table[tcb_index]->conn[sport]->mutex);
		if(tcb_table[tcb_index]->conn[sport] && tcb_table[tcb_index]->conn[sport]->server_state.state != CLOSED)
		{
			if (tcb_table[tcb_index]->conn[sport]->server_state.phase == NORMAL || tcb_table[tcb_index]->conn[sport]->server_state.phase == FAST_RTX)
			{
				current_time = timer.Start();
				if (tcb_table[tcb_index]->sliding_avg_window.size() && current_time > tcb_table[tcb_index]->sliding_avg_window.tailTime() + 5)
				{
					tcb_table[tcb_index]->rcv_thrughput = (tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time) == 0 ? tcb_table[tcb_index]->send_rate_upper : tcb_table[tcb_index]->sliding_avg_window.bytes() * RESOLUTION / tcb_table[tcb_index]->sliding_avg_window.timeInterval(current_time));
					tcb_table[tcb_index]->rcv_thrughput_approx = 0.875 * tcb_table[tcb_index]->rcv_thrughput_approx + 0.125 * tcb_table[tcb_index]->rcv_thrughput;
					BW_adaptation(sport, tcb_index);
#ifdef LOG_STAT
					log_data(sport, tcb_index);
#endif
				}
			}

		}

#ifndef DEBUG
		printf("%d  %u  %u  %u  %u  %u  %u  %u %hu\t\t\t\r", tcb_table[tcb_index]->conn[sport]->server_state.phase, tcb_table[tcb_index]->conn[sport]->server_state.snd_una, tcb_table[tcb_index]->conn[sport]->ack_interarrival_time, tcb_table[tcb_index]->conn[sport]->RTT, tcb_table[tcb_index]->conn[sport]->RTT_limit, tcb_table[tcb_index]->send_rate/1000, tcb_table[tcb_index]->rcv_thrughput_approx/1000, tcb_table[tcb_index]->conn[sport]->rcv_thrughput_approx/1000, sport);
#endif

		pthread_mutex_unlock(&tcb_table[tcb_index]->conn[sport]->mutex);
		pthread_mutex_unlock(&tcb_table[tcb_index]->mutex);
	}
#endif

}

pcap_t *inAdHandle, *outAdHandle;

void inline list_dev()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(-1);
	}

	if (alldevs == NULL){
		fprintf(stderr, "\nNo interfaces found! Make sure Pcap is installed.\n");
		return;
	}

	/* Print the list */
	for (d = alldevs; d; d=d->next)
	{
		ifprint(d);
	}

	pcap_freealldevs(alldevs);
}
void inline init_dev()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;

	int i = 0;
	int inum, onum;
	struct bpf_program fcode;

	char inner_ad_packet_filter[128];
	char outter_ad_packet_filter[128];

    char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(-1);
	}

	/* Print the list */
	for (d = alldevs; d; d=d->next)
	{
		++ i;
		ifprint(d);
	}

	if (i == 0)
	{
		printf("\nNo interface found! Make sure WinPcap is installed.\n");
		exit(-1);
	}

	printf("Enter the input interface number and output interface number (1-%d):", i);

	fscanf(test_file, "%d\n", &inum);
	fscanf(test_file, "%d\n", &onum);

	/* Check if the user specified a valid adapter */
	if ((inum < 1 || inum > i) && (onum < 1 || onum > i))
	{
		printf("\nAdapter number out of range.\n");
		exit(-1);
	}

	printf("%d %d\n", inum, onum);

	/* Jump to the selected input adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i ++);

	int sockfd;

    if(-1 == (sockfd = socket(PF_INET, SOCK_STREAM, 0)))
    {
        perror( "socket" );
        return;
    }

    struct ifreq req;

    bzero(&req, sizeof(struct ifreq));
    strcpy(req.ifr_name, d->name);
    ioctl(sockfd, SIOCGIFHWADDR, &req);

    sprintf(inner_ad_packet_filter, "(ip || icmp || arp || rarp) && not ether host %02x:%02x:%02x:%02x:%02x:%02x",
			        (unsigned char)req.ifr_hwaddr.sa_data[0],
                                (unsigned char)req.ifr_hwaddr.sa_data[1],
                                (unsigned char)req.ifr_hwaddr.sa_data[2],
                                (unsigned char)req.ifr_hwaddr.sa_data[3],
                                (unsigned char)req.ifr_hwaddr.sa_data[4],
                                (unsigned char)req.ifr_hwaddr.sa_data[5]);
	printf("The application filter of inner adapter is %s\n", inner_ad_packet_filter);

	/* Open the input adapter */
	/*
	if ((inAdHandle = pcap_open_live(d->name, 65535, 1, 1, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}
        */

	if ((inAdHandle = pcap_create(d->name, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	pcap_set_snaplen(inAdHandle, 65535);
	pcap_set_promisc(inAdHandle, 1);
	pcap_set_timeout(inAdHandle, 1);
	pcap_set_buffer_size(inAdHandle, 100000000);
	pcap_activate(inAdHandle);


	/* set input adapter capturing direction */
	if (pcap_setdirection(inAdHandle, PCAP_D_IN))
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	/* Compile the input filter */
	if (pcap_compile(inAdHandle, &fcode, inner_ad_packet_filter, 1, 0x0) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet input filter. Check the syntax.\n");
		exit(-1);
	}

	/* Set the input filter */
	if (pcap_setfilter(inAdHandle, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the input filter.\n");
		exit(-1);
	}

	printf("\nlistening on %s...\n", d->description);

	/* Jump to the selected output adapter */
	for (d = alldevs, i = 0; i < onum - 1; d = d->next, i ++);

	bzero(&req, sizeof(struct ifreq));
        strcpy(req.ifr_name, d->name);
        ioctl(sockfd, SIOCGIFHWADDR, &req);

	sprintf(outter_ad_packet_filter, "(ip || icmp || arp || rarp) && not ether host %02x:%02x:%02x:%02x:%02x:%02x",
								(unsigned char)req.ifr_hwaddr.sa_data[0],
                                (unsigned char)req.ifr_hwaddr.sa_data[1],
                                (unsigned char)req.ifr_hwaddr.sa_data[2],
                                (unsigned char)req.ifr_hwaddr.sa_data[3],
                                (unsigned char)req.ifr_hwaddr.sa_data[4],
                                (unsigned char)req.ifr_hwaddr.sa_data[5]);

	printf("The application filter of outter adapter is %s\n", outter_ad_packet_filter);

	/* Open the output adapter */
	if ((outAdHandle = pcap_open_live(d->name, 65535, 1, 1, errbuf)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the output adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}


	if (pcap_setdirection(outAdHandle, PCAP_D_IN))
	{
		fprintf(stderr,"\nUnable to open the input adapter. %s is not supported by WinPcap\n", d->name);
		exit(-1);
	}

	/* Compile the output filter */
	if (pcap_compile(outAdHandle, &fcode, outter_ad_packet_filter, 1, 0x0) < 0)
	{
		fprintf(stderr,"\nUnable to compile the packet output filter. Check the syntax.\n");
		exit(-1);
	}

	/* Set the output filter */
	if (pcap_setfilter(outAdHandle, &fcode) < 0)
	{
		fprintf(stderr,"\nError setting the output filter.\n");
		exit(-1);
	}

	printf("\nlistening on %s...\n", d->description);

  	close(sockfd);
	pcap_freealldevs(alldevs);
}
int main()
{
	init_dev();

	pthread_t th_in2out_capture, th_in2out_forward, th_out2in_capture, th_out2in_forward, th_scheduler, th_monitor;

	Forward *forward_out2in, *forward_in2out;
	DATA *data_out2in, *data_in2out;
	u_int circularBufferSize = CIRCULAR_QUEUE_SIZE, out2inDelay = END_TO_END_DELAY, in2outDelay =  END_TO_END_DELAY;

	forward_out2in = new Forward(inAdHandle, circularBufferSize, out2inDelay, CLIENT_TO_SERVER);
	forward_in2out = new Forward(outAdHandle, circularBufferSize, in2outDelay, SERVER_TO_CLIENT);
	data_out2in = new DATA(outAdHandle, inAdHandle, "eth0", "eth2", CLIENT_TO_SERVER, forward_out2in, forward_in2out);
	data_in2out = new DATA(inAdHandle, outAdHandle, "eth2", "eth0", SERVER_TO_CLIENT, forward_in2out, forward_out2in);

	pthread_create(&th_out2in_forward, 0, forwarder, (void *)forward_out2in);
	pthread_create(&th_in2out_forward, 0, forwarder, (void *)forward_in2out);
	pthread_create(&th_out2in_capture, 0, capturer, (void *)data_out2in);
	pthread_create(&th_in2out_capture, 0, capturer, (void *)data_in2out);
	pthread_create(&th_scheduler, 0, scheduler, (void *)data_in2out);
	//pthread_create(&th_monitor, 0, monitor, NULL);

	//struct sched_param param;
	//param.sched_priority = sched_get_priority_max(SCHED_RR);
	//pthread_setschedparam(th_out2in_capture, SCHED_RR, &param);
	//pthread_setschedparam(th_in2out_capture, SCHED_RR, &param);

	pthread_join(th_out2in_forward, NULL);
	pthread_join(th_in2out_forward, NULL);
	pthread_join(th_out2in_capture, NULL);
	pthread_join(th_in2out_capture, NULL);
	pthread_join(th_scheduler, NULL);
	//pthread_join(th_monitor, NULL);

	if (inAdHandle != NULL)
		pcap_close(inAdHandle);
	if (outAdHandle != NULL)
		pcap_close(outAdHandle);

	delete forward_out2in;
	delete forward_in2out;
	delete data_out2in;
	delete data_in2out;

	return 0;
}
