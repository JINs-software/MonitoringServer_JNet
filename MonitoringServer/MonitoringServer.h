#pragma once
#include "JNetCore.h"
#include "JNetDB.h"
#include "PerformanceCounter.h"
#include "MontServerConfig.h"
#include "MonitorProtocol.h"

//using SessionID = UINT64;

using namespace jnet;

class MonitoringServer : public JNetServer
{
private:
	struct stMontData {
		int dataValue = 0;
		int timeStamp = 0;

		int dataValueAccumulate = 0;
		int accunmulateCnt = 0;

		int dataAvr = 0;
		int dataMin = 0;
		int dataMax = 0;
	};
	
	std::vector<stMontData>		m_MontDataVec;

	PerformanceCounter*			m_PerfCounter;

	// 모니터링 대상 서버
	SessionID64				m_LoginServerSession;
	SessionID64				m_EchoGameServerSession;
	SessionID64				m_ChatServerSession;

	SessionID64				m_MontClientSessions[dfMAX_NUM_OF_MONT_CLIENT_TOOL];
	std::queue<BYTE>		m_EmptyIdxQueue;
	std::mutex				m_EmptyIdxQueueMtx;

	
	HANDLE					m_MontThread;
	
	JNetDBConnPool*			m_DBConnPool;
	HANDLE					m_DbConnThread;

	bool					m_StopThreads;

public:
	MonitoringServer(
		int32 dbConnectionCnt, const WCHAR* odbcConnStr,
		const char* serverIP, uint16 serverPort,
		BYTE packetCode_LAN, BYTE packetCode, BYTE packetSymmetricKey,
		bool recvBufferingMode,
		uint16 maximumOfSessions,
		uint32 numOfIocpConcurrentThrd, uint16 numOfIocpWorkerThrd,
		size_t tlsMemPoolUnitCnt, size_t tlsMemPoolUnitCapacity,
		bool tlsMemPoolMultiReferenceMode, bool tlsMemPoolPlacementNewMode,
		uint32 memPoolBuffAllocSize,
		uint32 sessionRecvBuffSize
	)
		: JNetServer(
			serverIP, serverPort,
			packetCode_LAN, packetCode, packetSymmetricKey,
			recvBufferingMode,
			maximumOfSessions,
			numOfIocpConcurrentThrd, numOfIocpWorkerThrd,
			tlsMemPoolUnitCnt, tlsMemPoolUnitCapacity, tlsMemPoolMultiReferenceMode, tlsMemPoolPlacementNewMode,
			memPoolBuffAllocSize, sessionRecvBuffSize
		),
		m_LoginServerSession(0), m_EchoGameServerSession(0), m_ChatServerSession(0),
		m_PerfCounter(NULL)

	{
		m_DBConnPool = new JNetDBConnPool();
		m_DBConnPool->Connect(dbConnectionCnt, odbcConnStr);

		memset(m_MontClientSessions, 0, sizeof(m_MontClientSessions));
		for (BYTE i = 0; i < dfMAX_NUM_OF_MONT_CLIENT_TOOL; i++) {
			m_EmptyIdxQueue.push(i);
		}

		m_MontDataVec.resize(dfMONITOR_DATA_TYPE_MAX_NUM, { 0 });
	}

	bool Start() {
		if (!JNetServer::Start()) {
			return false;
		}

		m_PerfCounter = new PerformanceCounter();
		m_PerfCounter->SetCounter(dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY, dfQUERY_MEMORY_NON_PAGED);
		m_PerfCounter->SetCounter(dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY, dfQUERY_MEMORY_AVAILABLE);
		m_PerfCounter->SetCpuUsageCounter();

		m_PerfCounter->SetEthernetCounter();

#if defined(MONT_SERVER_MONITORING_MODE)
		m_PerfCounter->SetProcessCounter(dfMONITOR_DATA_TYPE_MONT_SERVER_MEM, dfQUERY_PROCESS_USER_VMEMORY_USAGE, L"MonitoringServer");
#endif

		m_StopThreads = false;

		// DB 스레드
		m_DbConnThread = (HANDLE)_beginthreadex(NULL, 0, LoggingToDbFunc, this, 0, NULL);
		if (m_DbConnThread == INVALID_HANDLE_VALUE) {
			return false;
		}
		// 모니터링 서버 스레드
		m_MontThread = (HANDLE)_beginthreadex(NULL, 0, PerformanceCountFunc, this, 0, NULL);
		if (m_MontThread == INVALID_HANDLE_VALUE) {
			return false;
		}

		return true;
	}
	void Stop() {
		m_StopThreads = true;
		JNetServer::Stop();
	}

	virtual void OnRecv(UINT64 sessionID, JBuffer& recvBuff) override;
	virtual bool OnConnectionRequest(const SOCKADDR_IN& clientSockAddr) override { return true; }
	virtual void OnClientJoin(UINT64 sessionID, const SOCKADDR_IN& clientSockAddr) override {
		std::cout << "[OnClientJoin] sessionID: " << sessionID << std::endl;
	};
	virtual void OnClientLeave(UINT64 sessionID) {
		std::cout << "[OnClientLeave] sessionID: " << sessionID << std::endl;

		for (BYTE i = 0; i < dfMAX_NUM_OF_MONT_CLIENT_TOOL; i++) {
			if (m_MontClientSessions[i] == sessionID) {
				m_MontClientSessions[i] = 0;

				m_EmptyIdxQueueMtx.lock();
				m_EmptyIdxQueue.push(i);
				m_EmptyIdxQueueMtx.unlock();
				std::cout << "[OnClientLeave] 모니터링 클라이언트 연결 종료" << std::endl;

				return;
			}
		}

		if (m_LoginServerSession == sessionID) {
			m_LoginServerSession = 0;
			std::cout << "[OnClientLeave] 로그인 서버 연결 종료" << std::endl;
		}
		else if (m_EchoGameServerSession == sessionID) {
			m_EchoGameServerSession = 0;
			std::cout << "[OnClientLeave] 에코 게임 서버 연결 종료" << std::endl;
		}
		else if (m_ChatServerSession == sessionID) {
			m_ChatServerSession = 0;
			std::cout << "[OnClientLeave] 채팅 서버 연결 종료" << std::endl;
		}

	};

	void Process_SS_MONITOR_LOGIN(SessionID64 sessionID, int serverNo);
	void Process_SS_MONITOR_DATA_UPDATE(BYTE dataType, int dataVal, int timeStamp);
	bool Process_CS_MONITOR_TOOL_LOGIN(SessionID64 sessionID, char* loginSessionKey);

	void Send_MONT_DATA_TO_CLIENT();

	wstring Create_LogDbTable(SQL_TIMESTAMP_STRUCT  currentTime);
	void Insert_LogDB(const wstring& tableName, SQL_TIMESTAMP_STRUCT  currentTime, int serverNo, int type, int dataAvr, int dataMin, int dataMax);

	static UINT __stdcall PerformanceCountFunc(void* arg);
	static UINT __stdcall LoggingToDbFunc(void* arg);
};

