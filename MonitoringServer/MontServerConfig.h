#pragma once

//#define MONTSERVER_ASSERT

#define MONTSERVER_PROTOCOL_CODE_LAN				99
#define MONTSERVER_PROTOCOL_CODE					109
#define MONTSERVER_PACKET_KEY						30

#define MONT_DB_CONN_COUNT							1
#define MOND_ODBC_CONNECTION_STRING					L"Driver={MySQL ODBC 8.4 ANSI Driver};Server=127.0.0.1;Database=logdb;User=mainserver;Password=607281;Option=3;"
																						// 10.0.1.2
#define MONT_SERVER_IP								NULL
#define MONT_SERVER_PORT							12121

#define MONT_MAX_CONNECTIONS						20

#define MONT_TLS_MEM_POOL_DEFAULT_UNIT_CNT			10
#define MONT_TLS_MEM_POOL_DEFAULT_UNIT_CAPACITY		10

#define MONT_SERIAL_BUFFER_SIZE						500
#define MONT_SERV_SESSION_RECV_BUFF_SIZE			1000

#define dfMAX_NUM_OF_MONT_CLIENT_TOOL				5