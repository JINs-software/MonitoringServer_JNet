#include "MonitoringServer.h"
#include "MonitorProtocol.h"
#include <sstream>

void MonitoringServer::OnRecv(UINT64 sessionID, JBuffer& recvBuff)
{
	while (recvBuff.GetUseSize() > sizeof(WORD)) {			/// ????		// [TO DO] msgHdr.len������ ��ť�� �ϴ� ������ ����
		WORD type;
		recvBuff.Peek(&type);

		switch (type)
		{
		case en_PACKET_SS_MONITOR_LOGIN:
		{
			if (recvBuff.GetUseSize() < sizeof(WORD) + sizeof(int)) {
				break;
			}

			recvBuff >> type;
			int serverNo;
			recvBuff >> serverNo;
			Process_SS_MONITOR_LOGIN(sessionID, serverNo);
		}
		break;
		case en_PACKET_SS_MONITOR_DATA_UPDATE:
		{
			if (recvBuff.GetUseSize() < sizeof(WORD) + sizeof(BYTE) + sizeof(int) + sizeof(int)) {
				break;
			}

			recvBuff >> type;
			BYTE dataType;
			int dataValue;
			int timeStamp;
			recvBuff >> dataType;
			recvBuff >> dataValue;
			recvBuff >> timeStamp;
			Process_SS_MONITOR_DATA_UPDATE(dataType, dataValue, timeStamp);
		}
		break;
		case en_PACKET_CS_MONITOR_TOOL_REQ_LOGIN:
		{
			if (recvBuff.GetUseSize() < sizeof(WORD) + sizeof(char) * 32) {
				break;
			}

			recvBuff >> type;
			char	loginSessionKey[32];
			recvBuff.Dequeue((BYTE*)loginSessionKey, sizeof(loginSessionKey));
			if (!Process_CS_MONITOR_TOOL_LOGIN(sessionID, loginSessionKey)) {
				Disconnect(sessionID);
				return;
			}
		}
		break;
		default:
#if defined(MONTSERVER_ASSERT)
			DebugBreak();
#endif
			break;
		}
	}

#if defined(MONTSERVER_ASSERT)
	if (recvBuff.GetUseSize() > 0) {
		DebugBreak();
	}
#endif
}

void MonitoringServer::Process_SS_MONITOR_LOGIN(SessionID64 sessionID, int serverNo)
{
	// ���� ID <-> ���� ���� ����
	switch (serverNo)
	{
	case dfSERVER_LOGIN_SERVER:
	{
		if (m_LoginServerSession == 0) {
			m_LoginServerSession = sessionID;
		}
		else {
			// �ߺ� �α���
			std::cout << "�α��� ���� �ߺ� �α���" << std::endl;
		}
	}
		break;
	case dfSERVER_ECHO_GAME_SERVER:
	{
		if (m_EchoGameServerSession == 0) {
			m_EchoGameServerSession = sessionID;
		}
		else {
			// �ߺ� �α���
			std::cout << "���� ���� �ߺ� �α���" << std::endl;
		}
	}
		break;
	case dfSERVER_CHAT_SERVER:
	{
		if (m_ChatServerSession == 0) {
			m_ChatServerSession = sessionID;
		}
		else {
			// �ߺ� �α���
			std::cout << "ä�� ���� �ߺ� �α���" << std::endl;
		}
	}
		break;
	default:
		break;
	}
}

void MonitoringServer::Process_SS_MONITOR_DATA_UPDATE(BYTE dataType, int dataVal, int timeStamp)
{
	if (dataType < m_MontDataVec.size()) {
		m_MontDataVec[dataType].dataValue = dataVal;
		m_MontDataVec[dataType].timeStamp = timeStamp;

		m_MontDataVec[dataType].dataValueAccumulate += dataVal;
		m_MontDataVec[dataType].accunmulateCnt += 1;
		if (m_MontDataVec[dataType].accunmulateCnt == 1) {
			m_MontDataVec[dataType].dataMin = m_MontDataVec[dataType].dataMax = m_MontDataVec[dataType].dataValue;
		}
		m_MontDataVec[dataType].dataMin = min(m_MontDataVec[dataType].dataValue, m_MontDataVec[dataType].dataMin);
		m_MontDataVec[dataType].dataMax = max(m_MontDataVec[dataType].dataValue, m_MontDataVec[dataType].dataMax);
	}
}

bool MonitoringServer::Process_CS_MONITOR_TOOL_LOGIN(SessionID64 sessionID, char* loginSessionKey)
{
#if defined(MONTSERVER_ASSERT)
	for (BYTE i = 0; i < dfMAX_NUM_OF_MONT_CLIENT_TOOL; i++) {
		if (m_MontClientSessions[i] == sessionID) {
#if defined(MONTSERVER_ASSERT)
			DebugBreak();
#else
			std::cout << "����͸� Ŭ���̾�Ʈ �� �ߺ� �α���" << std::endl;
			return;
#endif
		}
	}
#endif
	bool idxQueueEmpty = false;
	m_EmptyIdxQueueMtx.lock();
	if (m_EmptyIdxQueue.empty()) {
		std::cout << "����͸� Ŭ���̾�Ʈ �� ���� ���� �� �ʰ�(�α��� �Ұ�)" << std::endl;
		idxQueueEmpty = true;
	}
	else {
		m_MontClientSessions[m_EmptyIdxQueue.front()] = sessionID;
		m_EmptyIdxQueue.pop();
	}
	m_EmptyIdxQueueMtx.unlock();

	if (!idxQueueEmpty) {
		JBuffer* resPacket = AllocSerialBuff();
		stMSG_HDR* hdr = resPacket->DirectReserve<stMSG_HDR>();
		hdr->code = MONTSERVER_PROTOCOL_CODE;
		hdr->len = sizeof(WORD) + sizeof(BYTE);
		hdr->randKey = -1;	// SendPacket���� ���ڵ� ����
		*resPacket << (WORD)en_PACKET_CS_MONITOR_TOOL_RES_LOGIN;
		*resPacket << (BYTE)dfMONITOR_TOOL_LOGIN_OK;
		SendPacket(sessionID, resPacket);

		return true;
	}
	else {
		return false;
	}
}


void MonitoringServer::Send_MONT_DATA_TO_CLIENT() {
	JBuffer* sendBuff = AllocSerialBuff();

#if defined (MONT_SERVER_MONITORING_MODE)
	for (BYTE dataType = dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL; dataType <= dfMONITOR_DATA_TYPE_MONT_SERVER_CPU; dataType++) {
		if (sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)) {
			DebugBreak();
		}
		stMSG_HDR* hdr;
		hdr = sendBuff->DirectReserve<stMSG_HDR>();
		hdr->code = dfPACKET_CODE;
		hdr->len = sizeof(stMSG_MONT_DATA_UPDATE);
		hdr->randKey = (BYTE)-1;
		stMSG_MONT_DATA_UPDATE* body = sendBuff->DirectReserve<stMSG_MONT_DATA_UPDATE>();
		body->Type = en_PACKET_CS_MONITOR_TOOL_DATA_UPDATE;
		body->DataType = dataType;
		body->DataValue = m_MontDataVec[dataType].dataValue;
		body->TimeStamp = m_MontDataVec[dataType].timeStamp;
	}
#else
	for (BYTE dataType = dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL; dataType <= dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY; dataType++) {
		if (sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)) {
			std::cout << "sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)" << std::endl;
			DebugBreak();
		}
		stMSG_HDR* hdr;
		hdr = sendBuff->DirectReserve<stMSG_HDR>();
		hdr->code = MONTSERVER_PROTOCOL_CODE;
		hdr->len = sizeof(stMSG_MONT_DATA_UPDATE);
		hdr->randKey = (BYTE)-1;
		stMSG_MONT_DATA_UPDATE* body = sendBuff->DirectReserve<stMSG_MONT_DATA_UPDATE>();
		body->Type = en_PACKET_CS_MONITOR_TOOL_DATA_UPDATE;
		body->DataType = dataType;
		body->DataValue = m_MontDataVec[dataType].dataValue;
		body->TimeStamp = m_MontDataVec[dataType].timeStamp;
	}
#endif
	if (m_MontDataVec[dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN].dataValue == 1) {
		for (BYTE dataType = dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN; dataType <= dfMONITOR_DATA_TYPE_LOGIN_PACKET_POOL; dataType++) {
			if (sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)) {
				std::cout << "sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)" << std::endl;
				DebugBreak();
			}
			stMSG_HDR* hdr;
			hdr = sendBuff->DirectReserve<stMSG_HDR>();
			hdr->code = MONTSERVER_PROTOCOL_CODE;
			hdr->len = sizeof(stMSG_MONT_DATA_UPDATE);
			hdr->randKey = (BYTE)-1;
			stMSG_MONT_DATA_UPDATE* body = sendBuff->DirectReserve<stMSG_MONT_DATA_UPDATE>();
			body->Type = en_PACKET_CS_MONITOR_TOOL_DATA_UPDATE;
			body->DataType = dataType;
			body->DataValue = m_MontDataVec[dataType].dataValue;
			body->TimeStamp = m_MontDataVec[dataType].timeStamp;
		}

		// Ÿ�� �ƿ� üũ
		if (time(NULL) > m_MontDataVec[dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN].timeStamp + 10) {
			memset(&m_MontDataVec[dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN], 0, sizeof(stMontData) * (dfMONITOR_DATA_TYPE_LOGIN_PACKET_POOL - dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN + 1));
		}
	}
	if (m_MontDataVec[dfMONITOR_DATA_TYPE_GAME_SERVER_RUN].dataValue == 1) {
		for (BYTE dataType = dfMONITOR_DATA_TYPE_GAME_SERVER_RUN; dataType <= dfMONITOR_DATA_TYPE_GAME_PACKET_POOL; dataType++) {
			if (sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)) {
				std::cout << "sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)" << std::endl;
				DebugBreak();
			}
			stMSG_HDR* hdr;
			hdr = sendBuff->DirectReserve<stMSG_HDR>();
			hdr->code = MONTSERVER_PROTOCOL_CODE;
			hdr->len = sizeof(stMSG_MONT_DATA_UPDATE);
			hdr->randKey = (BYTE)-1;
			stMSG_MONT_DATA_UPDATE* body = sendBuff->DirectReserve<stMSG_MONT_DATA_UPDATE>();
			body->Type = en_PACKET_CS_MONITOR_TOOL_DATA_UPDATE;
			body->DataType = dataType;
			body->DataValue = m_MontDataVec[dataType].dataValue;
			body->TimeStamp = m_MontDataVec[dataType].timeStamp;
		}

		if (time(NULL) > m_MontDataVec[dfMONITOR_DATA_TYPE_GAME_SERVER_RUN].timeStamp + 10) {
			memset(&m_MontDataVec[dfMONITOR_DATA_TYPE_GAME_SERVER_RUN], 0, sizeof(stMontData) * (dfMONITOR_DATA_TYPE_GAME_PACKET_POOL - dfMONITOR_DATA_TYPE_GAME_SERVER_RUN + 1));
		}
	}
	if (m_MontDataVec[dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN].dataValue == 1) {
		for (BYTE dataType = dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN; dataType <= dfMONITOR_DATA_TYPE_CHAT_UPDATEMSG_POOL; dataType++) {
			if (sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)) {
				std::cout << "sendBuff->GetFreeSize() < sizeof(stMSG_HDR) + sizeof(stMSG_MONT_DATA_UPDATE)" << std::endl;
				DebugBreak();
			}
			stMSG_HDR* hdr;
			hdr = sendBuff->DirectReserve<stMSG_HDR>();
			hdr->code = MONTSERVER_PROTOCOL_CODE;
			hdr->len = sizeof(stMSG_MONT_DATA_UPDATE);
			hdr->randKey = (BYTE)-1;
			stMSG_MONT_DATA_UPDATE* body = sendBuff->DirectReserve<stMSG_MONT_DATA_UPDATE>();
			body->Type = en_PACKET_CS_MONITOR_TOOL_DATA_UPDATE;
			body->DataType = dataType;
			body->DataValue = m_MontDataVec[dataType].dataValue;
			body->TimeStamp = m_MontDataVec[dataType].timeStamp;
		}

		if (time(NULL) > m_MontDataVec[dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN].timeStamp + 10) {
			memset(&m_MontDataVec[dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN], 0, sizeof(stMontData) * (dfMONITOR_DATA_TYPE_CHAT_UPDATEMSG_POOL - dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN + 1));
		}
	}

	for (BYTE i = 0; i < dfMAX_NUM_OF_MONT_CLIENT_TOOL; i++) {
		SessionID64 sessionID = m_MontClientSessions[i];
		if (sessionID == 0) {
			continue;
		}
		AddRefSerialBuff(sendBuff);
		SendPacket(sessionID, sendBuff);
	}

	FreeSerialBuff(sendBuff);
}



wstring MonitoringServer::Create_LogDbTable(SQL_TIMESTAMP_STRUCT  currentTime)
{
	JNetDBConn* dbConn = m_DBConnPool->Pop();
	if (dbConn == NULL) {
		DebugBreak();
	}
	dbConn->Unbind();

	SQLLEN logtimeLen = sizeof(currentTime);
	SQLLEN len = 0;

	// ���̺� �̸� (_month)
	std::wstringstream tableName;
	tableName << L"monitorlog_" << currentTime.year << (currentTime.month < 10 ? L"0" : L"") << currentTime.month;

	// ���̺� ���� ���� Ȯ�� ����
	std::wstringstream checkTableQuery;
	checkTableQuery << L"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'logdb' AND table_name = '" << tableName.str() << L"'";

	wstring queryStr = checkTableQuery.str();
	const WCHAR* query = queryStr.c_str();
	if (!dbConn->Execute(query)) {
#if defined(MONTSERVER_ASSERT)
		DebugBreak();
#else
		std::cout << "���̺� ���� ���� Ȯ�� ���� Execute ����!!!" << std::endl;
		return L"";
#endif
	}

	bool tableExists = false;
	dbConn->Fetch();
	INT32 sqlData;
	if (!dbConn->GetSQLData(sqlData)) {
#if defined(MONTSERVER_ASSERT)
		DebugBreak();
#else
		std::cout << "���̺� ���� ���� Ȯ�� ���� ���� �� GetSQLData ���� ��ȯ!!!" << std::endl;
		return L"";
#endif
	}
	else {
		if (sqlData > 0) {
			tableExists = true;
		}
	}

	// ���ο� ���̺� ���� ����(�� ��)
	if (!tableExists) {
		dbConn->Unbind();

		std::wstringstream createTableQuery;
		createTableQuery << L"CREATE TABLE `logdb`.`" << tableName.str() << L"` ("
			<< L"`no` BIGINT NOT NULL AUTO_INCREMENT, "
			<< L"`logtime` DATETIME, "
			<< L"`serverno` INT NOT NULL, "
			<< L"`type` INT NOT NULL, "
			<< L"`avr` INT NOT NULL, "
			<< L"`min` INT NOT NULL, "
			<< L"`max` INT NOT NULL, "
			<< L"PRIMARY KEY(`no`))";

		// ���̺� ����
		queryStr = createTableQuery.str();
		query = queryStr.c_str();
		if (!dbConn->Execute(query)) {
#if defined(MONTSERVER_ASSERT)
			DebugBreak();
#else
			std::cout << "���ο� ���̺� ���� ����(�� ��) Execute ����!!!" << std::endl;
			return L"";
#endif
		}
#if defined(MONT_SERVER_DB_CONSOLE_LOG)
		else {
			std::wcout << L"[DB] Create Table: logdb." << tableName.str() << std::endl;
		}
#endif
	}

	m_DBConnPool->Push(dbConn);
	return tableName.str();
}

void MonitoringServer::Insert_LogDB(const wstring& tableName, SQL_TIMESTAMP_STRUCT  currentTime, int serverNo, int type, int dataAvr, int dataMin, int dataMax)
{
	JNetDBConn* dbConn = m_DBConnPool->Pop();
	if (dbConn == NULL) {
		DebugBreak();
	}
	dbConn->Unbind();

	SQLLEN logtimeLen = sizeof(currentTime);
	SQLLEN len = 0;

	// ���� ���ε�
	dbConn->BindParam(1, SQL_C_TYPE_TIMESTAMP, SQL_TYPE_TIMESTAMP, logtimeLen, &currentTime, &logtimeLen);
	dbConn->BindParam(2, SQL_C_LONG, SQL_INTEGER, sizeof(serverNo), &serverNo, &len);
	dbConn->BindParam(3, SQL_C_LONG, SQL_INTEGER, sizeof(type), &type, &len);
	dbConn->BindParam(4, SQL_C_LONG, SQL_INTEGER, sizeof(dataAvr), &dataAvr, &len);
	dbConn->BindParam(5, SQL_C_LONG, SQL_INTEGER, sizeof(dataMin), &dataMin, &len);
	dbConn->BindParam(6, SQL_C_LONG, SQL_INTEGER, sizeof(dataMax), &dataMax, &len);

	// �α� �� ���� SQL ����
	wstring queryWstr = L"INSERT INTO `logdb`.`" + tableName + L"` (`logtime`, `serverno`, `type`, `avr`, `min`, `max`) VALUES (?, ?, ?, ?, ?, ?)";
	const WCHAR* query = queryWstr.c_str();
	if (!dbConn->Execute(query)) {
#if defined(MONTSERVER_ASSERT)
		DebugBreak();
#else
		std::cout << "�α� �� ���� ���� Execute ����!!!" << std::endl;
		return;
#endif
	}
#if defined(MONT_SERVER_DB_CONSOLE_LOG)
	else {
		std::wcout << L"[DB] Insert Query Complete: ";
		std::wcout << L"serverNo: " << serverNo << L", type: " << type << L", Avr: " << dataAvr << ", Min: " << dataMin << L", Max: " << dataMax << std::endl;
	}
#endif

	m_DBConnPool->Push(dbConn);
}

UINT __stdcall MonitoringServer::PerformanceCountFunc(void* arg)
{
	MonitoringServer* montserver = (MonitoringServer*)arg;
	montserver->AllocTlsMemPool();

	while (!montserver->m_StopThreads) {
		time_t now = time(NULL);
		//////////////////////////////////////////////////
		// ī��Ʈ ����
		//////////////////////////////////////////////////
		montserver->m_PerfCounter->ResetPerfCounterItems();

		// ���� ���μ��� ���� ����
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataValue = montserver->m_PerfCounter->ProcessorTotal();
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataValueAccumulate += montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataValue;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].accunmulateCnt += 1;
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].accunmulateCnt == 1) {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataMin = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataMax = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataValue;
		}
		else {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataMin = min(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataMin);
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataMax = max(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL].dataMax);
		}

		// ���� ��-������ Ǯ ���� ����
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValue = montserver->m_PerfCounter->GetPerfCounterItem(dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY);
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValue /= (1024 * 1024);	// ��-������ Ǯ MBytes
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValueAccumulate += montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValue;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].accunmulateCnt += 1;
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].accunmulateCnt == 1) {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataMin = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataMax = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValue;
		}
		else {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataMin = min(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataMin);
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataMax = max(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NONPAGED_MEMORY].dataMax);
		}


		// ���� ���� ����Ʈ ���� ����
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue = montserver->m_PerfCounter->GetPerfEthernetRecvBytes();
		//montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue = montserver->m_PerfCounter->GetPerfCounterItem(dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV);
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue /= 1024;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValueAccumulate += montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].accunmulateCnt += 1;
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].accunmulateCnt == 1) {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataMin = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataMax = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue;
		}
		else {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataMin = min(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataMin);
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataMax = max(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_RECV].dataMax);
		}

		// ���� �۽� ����Ʈ ���� ����
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue = montserver->m_PerfCounter->GetPerfEthernetSendBytes();
		//montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue = montserver->m_PerfCounter->GetPerfCounterItem(dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND);
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue /= 1024;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValueAccumulate += montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].accunmulateCnt += 1;
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].accunmulateCnt == 1) {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataMin = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataMax = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue;
		}
		else {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataMin = min(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataMin);
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataMax = max(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_NETWORK_SEND].dataMax);
		}

		// ���� ��� ���� �޸� ���� ����
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataValue = montserver->m_PerfCounter->GetPerfCounterItem(dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY);
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataValueAccumulate += montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataValue;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].accunmulateCnt += 1;
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].accunmulateCnt == 1) {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataMin = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataMax = montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataValue;
		}
		else {
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataMin = min(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataMin);
			montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataMax = max(montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataValue, montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY].dataMax);
		}
		
#if defined(MONT_SERVER_MONITORING_MODE)
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONT_SERVER_RUN].dataValue = 1;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONT_SERVER_RUN].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONT_SERVER_CPU].dataValue = montserver->m_PerfCounter->ProcessTotal();
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONT_SERVER_CPU].timeStamp = now;
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONT_SERVER_MEM].dataValue = montserver->m_PerfCounter->GetPerfCounterItem(dfMONITOR_DATA_TYPE_MONT_SERVER_MEM);
		montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_MONT_SERVER_MEM].timeStamp = now;
#endif

		montserver->Send_MONT_DATA_TO_CLIENT();

		Sleep(1000);
	}


	return 0;
}

UINT __stdcall MonitoringServer::LoggingToDbFunc(void* arg)
{
	MonitoringServer* montserver = (MonitoringServer*)arg;

	while (!montserver->m_StopThreads) {
		Sleep(60000);

		auto now = std::chrono::system_clock::now();
		std::time_t now_time = std::chrono::system_clock::to_time_t(now);
		std::tm* now_tm = std::localtime(&now_time);

		SQL_TIMESTAMP_STRUCT timestamp;
		timestamp.year = now_tm->tm_year + 1900;
		timestamp.month = now_tm->tm_mon + 1;
		timestamp.day = now_tm->tm_mday;
		timestamp.hour = now_tm->tm_hour;
		timestamp.minute = now_tm->tm_min;
		timestamp.second = now_tm->tm_sec;
		timestamp.fraction = 0;

		wstring tableName = montserver->Create_LogDbTable(timestamp);
		if (tableName == L"") {
			std::cout << ">Create_LogDbTable ���� ��ȯ!" << std::endl;
			break;
		}

		// ���� ���� 
		for (BYTE dataType = dfMONITOR_DATA_TYPE_MONITOR_CPU_TOTAL; dataType <= dfMONITOR_DATA_TYPE_MONITOR_AVAILABLE_MEMORY; dataType++) {
			int dataValueAcc = montserver->m_MontDataVec[dataType].dataValueAccumulate;
			int accCnt = montserver->m_MontDataVec[dataType].accunmulateCnt;

			if (accCnt != 0) {
				montserver->m_MontDataVec[dataType].dataAvr = dataValueAcc / accCnt;
			}

			// �α� ���� DB ����
			montserver->Insert_LogDB(tableName, timestamp, dfSERVER_SYSTEM, dataType, montserver->m_MontDataVec[dataType].dataAvr, montserver->m_MontDataVec[dataType].dataMin, montserver->m_MontDataVec[dataType].dataMax);

			montserver->m_MontDataVec[dataType].dataValueAccumulate = 0;
			montserver->m_MontDataVec[dataType].accunmulateCnt = 0;
			montserver->m_MontDataVec[dataType].dataMin = 0;
			montserver->m_MontDataVec[dataType].dataMax = 0;
		}

		// �α��� ����
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN].dataValue == 1) {
			for (BYTE dataType = dfMONITOR_DATA_TYPE_LOGIN_SERVER_RUN; dataType <= dfMONITOR_DATA_TYPE_LOGIN_PACKET_POOL; dataType++) {
				int dataValueAcc = montserver->m_MontDataVec[dataType].dataValueAccumulate;
				int accCnt = montserver->m_MontDataVec[dataType].accunmulateCnt;

				if (accCnt != 0) {
					montserver->m_MontDataVec[dataType].dataAvr = dataValueAcc / accCnt;
				}
				montserver->Insert_LogDB(tableName, timestamp, dfSERVER_LOGIN_SERVER, dataType, montserver->m_MontDataVec[dataType].dataAvr, montserver->m_MontDataVec[dataType].dataMin, montserver->m_MontDataVec[dataType].dataMax);

				montserver->m_MontDataVec[dataType].dataValueAccumulate = 0;
				montserver->m_MontDataVec[dataType].accunmulateCnt = 0;
				montserver->m_MontDataVec[dataType].dataMin = 0;
				montserver->m_MontDataVec[dataType].dataMax = 0;
			}
		}

		// ����-���� ����
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_GAME_SERVER_RUN].dataValue == 1) {
			for (BYTE dataType = dfMONITOR_DATA_TYPE_GAME_SERVER_RUN; dataType <= dfMONITOR_DATA_TYPE_GAME_PACKET_POOL; dataType++) {
				int dataValueAcc = montserver->m_MontDataVec[dataType].dataValueAccumulate;
				int accCnt = montserver->m_MontDataVec[dataType].accunmulateCnt;

				if (accCnt != 0) {
					montserver->m_MontDataVec[dataType].dataAvr = dataValueAcc / accCnt;
				}
				montserver->Insert_LogDB(tableName, timestamp, dfSERVER_ECHO_GAME_SERVER, dataType, montserver->m_MontDataVec[dataType].dataAvr, montserver->m_MontDataVec[dataType].dataMin, montserver->m_MontDataVec[dataType].dataMax);

				montserver->m_MontDataVec[dataType].dataValueAccumulate = 0;
				montserver->m_MontDataVec[dataType].accunmulateCnt = 0;
				montserver->m_MontDataVec[dataType].dataMin = 0;
				montserver->m_MontDataVec[dataType].dataMax = 0;
			}

		}

		// ä�� ����
		if (montserver->m_MontDataVec[dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN].dataValue == 1) {
			for (BYTE dataType = dfMONITOR_DATA_TYPE_CHAT_SERVER_RUN; dataType <= dfMONITOR_DATA_TYPE_CHAT_UPDATEMSG_POOL; dataType++) {
				int dataValueAcc = montserver->m_MontDataVec[dataType].dataValueAccumulate;
				int accCnt = montserver->m_MontDataVec[dataType].accunmulateCnt;

				if (accCnt != 0) {
					montserver->m_MontDataVec[dataType].dataAvr = dataValueAcc / accCnt;
				}
				montserver->Insert_LogDB(tableName, timestamp, dfSERVER_CHAT_SERVER, dataType, montserver->m_MontDataVec[dataType].dataAvr, montserver->m_MontDataVec[dataType].dataMin, montserver->m_MontDataVec[dataType].dataMax);

				montserver->m_MontDataVec[dataType].dataValueAccumulate = 0;
				montserver->m_MontDataVec[dataType].accunmulateCnt = 0;
				montserver->m_MontDataVec[dataType].dataMin = 0;
				montserver->m_MontDataVec[dataType].dataMax = 0;
			}
		}
	}

	return 0;
}
