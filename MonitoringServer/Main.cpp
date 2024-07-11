#include "MonitoringServer.h"
#include <conio.h>

int main() {
	//MonitoringServer(
	//	int32 dbConnectionCnt, const WCHAR * odbcConnStr,
	//	const char* serverIP, uint16 serverPort,
	//	BYTE packetCode_LAN, BYTE packetCode, BYTE packetSymmetricKey,
	//	bool recvBufferingMode,
	//	uint16 maximumOfSessions,
	//	uint32 numOfIocpConcurrentThrd, uint16 numOfIocpWorkerThrd,
	//	size_t tlsMemPoolUnitCnt, size_t tlsMemPoolUnitCapacity,
	//	bool tlsMemPoolMultiReferenceMode, bool tlsMemPoolPlacementNewMode,
	//	uint32 memPoolBuffAllocSize,
	//	uint32 sessionRecvBuffSize
	//)
	MonitoringServer montserver(
		MONT_DB_CONN_COUNT, MOND_ODBC_CONNECTION_STRING, 
		MONT_SERVER_IP, MONT_SERVER_PORT, MONT_MAX_CONNECTIONS,
		MONTSERVER_PROTOCOL_CODE_LAN, MONTSERVER_PROTOCOL_CODE, MONTSERVER_PACKET_KEY,
		false, 10, 0, 1,
		MONT_TLS_MEM_POOL_DEFAULT_UNIT_CNT, MONT_TLS_MEM_POOL_DEFAULT_UNIT_CAPACITY,
		true, false, 
		MONT_SERIAL_BUFFER_SIZE, MONT_SERV_SESSION_RECV_BUFF_SIZE
		);

	montserver.Start();

	char ctr;
	while (true) {
		if (_kbhit()) {
			ctr = _getch();
			if (ctr == 'q' || 'Q') {
				break;
			}
		}

		Sleep(10000);
	}

	montserver.Stop();

	return 0;
}