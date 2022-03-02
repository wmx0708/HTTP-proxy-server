#include <iostream>
#include <fstream>
#include <stdio.h>
#include <windows.h>
#include <process.h>
#include <string.h>
#include <winsock.h>
#include <errno.h>

using namespace std;

#pragma comment(lib,"Ws2_32.lib")
#define MAXSIZE 65507
#define HTTP_PORT 80
#define HTTPS_PORT 443

//������
const char* blacklist[10] = { "mail.hit.edu.cn / ","yzb.buaa.edu.cn / ","hituc.hit.edu.cn / " };
int blacklistnum = 3;

//httpͷ��
struct HttpHeader {
	char method[4];
	char url[1024];
	char host[1024];
	char cookie[1024 * 10];
	HttpHeader() {
		ZeroMemory(this, sizeof(HttpHeader));
	}
};
bool InitSocket();//scoket��ʼ��
void ParseHttpHead(char* buffer, HttpHeader* httpHeader);//����httpͷ
boolean ParseDate(char* buffer, char* field, char* tempDate);
void makeNewHTTP(char* buffer, char* value);
void makeFilename(char* url, char* filename);
void makeCache(char* buffer, char* url);
void getCache(char* buffer, char* filename);
bool ConnectToServer(SOCKET* serverSocket, char* host);
unsigned int _stdcall ProxyThread(LPVOID lpParameter);
//�������������
SOCKET ProxyServer;//�������׽������ڼ���
SOCKADDR_IN ProxyServerAddr;//�׽��ֵ�ַ
const int ProxyPort = 10240;//����������˿�

bool haveCache = false;
bool needCache = true;

struct ProxyParam {
	SOCKET cilentSocket;
	SOCKET serverSocket;
};
unsigned long ul = 1;
int main(int argc, TCHAR* argv[]) {
	printf("�����������������\n");
	printf("��ʼ��...\n");
	if (!InitSocket()) {
		printf("��������ʼ��ʧ��\n");
		return -1;
	}
	printf("����������������У����� : %d\n", ProxyPort);
	SOCKET acceptSocket = INVALID_SOCKET;
	ProxyParam* lpProxyParam;
	HANDLE hThread;//�����߳̾��
	DWORD dwThreadID;//�߳�ID
	//���������ѭ������
	while (true) {
		haveCache = false;
		needCache = true;
		acceptSocket = accept(ProxyServer, NULL, NULL);//���տͻ��˵�����
		lpProxyParam = new ProxyParam;
		if (lpProxyParam == NULL) {
			continue;
		}
		lpProxyParam->cilentSocket = acceptSocket;//���������ظ��ͻ��˵������׽���
		hThread = (HANDLE)_beginthreadex(NULL, 0, &ProxyThread, (LPVOID)lpProxyParam, 0, 0);//�����߳�
		CloseHandle(hThread);//�黹�߳̾����Դ
		Sleep(200);
	}
	closesocket(ProxyServer);//�رձ����׽���
	WSACleanup();
	return 0;
}

//��ʼ���׽���
bool InitSocket() {
	//�����׽��ֿ⣨���룩
	WORD wVersionRequested;
	WSADATA wsaData;
	int err; ////�׽��ּ���ʱ������ʾ
	wVersionRequested = MAKEWORD(2, 2); //�汾��2.2
										//����dll�ļ�Socket��
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {//�Ҳ���winsock.dll
		printf("����winsock.dllʧ�ܣ�����%d", WSAGetLastError());
		return false;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		printf("�����ҵ���ȷ��winsock�汾\n");
		WSACleanup();
		return false;
	}
	ProxyServer = socket(AF_INET, SOCK_STREAM, 0); //����TCP���ӵ��׽���
	if (INVALID_SOCKET == ProxyServer) {
		printf("�����׽���ʧ�ܣ��������Ϊ %d\n", WSAGetLastError());
		return false;
	}
	ProxyServerAddr.sin_family = AF_INET;
	ProxyServerAddr.sin_port = htons(ProxyPort); //ָ�����������Ķ˿�
	ProxyServerAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//0.0.0.0INADDR_ANY
	if (bind(ProxyServer, (SOCKADDR*)&ProxyServerAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		printf("���׽���ʧ��\n");
		return false;
	}
	if (listen(ProxyServer, SOMAXCONN) == SOCKET_ERROR) {
		printf("�����˿�%dʧ��", ProxyPort);
		return false;
	}
	return true;
}

//����TCP�����е�HTTPͷ��
bool ParseHttpHead(char* buffer, HttpHeader* httpHeader, bool http_flag) {
	char* p;
	char* ptr;
	const char* delim = "\r\n";
	//���洢��buffer�е�httpͷ�ַ����ָ�
	p = strtok_s(buffer, delim, &ptr);
	printf("%s\n", p);
	if (p[0] == 'G') {  //GET��ʽ
		memcpy(httpHeader->method, "GET", 3);
		memcpy(httpHeader->url, &p[4], strlen(p) - 13);  //url�ĳ���
	}
	else if (p[0] == 'P') {  //POST��ʽ
		memcpy(httpHeader->method, "POST", 4);
		memcpy(httpHeader->url, &p[5], strlen(p) - 14);
	}
	//printf("%s\n", httpHeader->url);
	p = strtok_s(NULL, delim, &ptr);//delim="/r/n"
	while (p) {
		switch (p[0]) {
		case 'H':  //host
			//�ж������Ƿ��С���443���˿���ʽ�������ͨ��http������httpsͷ���������ӡ���443������
			if (strstr(p, (char*)":443"))
			{
				http_flag = 1;
				memcpy(httpHeader->host, &p[6], strlen(p) - 10);//���http���ȥ4���ֽڡ���443��
			}
			else {
				memcpy(httpHeader->host, &p[6], strlen(p) - 6);
			}
			break;
		case 'C': //cookie
			if (strlen(p) > 8) {
				char header[8];
				ZeroMemory(header, sizeof(header));
				memcpy(header, p, 6);
				if (!strcmp(header, "Cookie")) {
					memcpy(httpHeader->cookie, &p[8], strlen(p) - 8);
				}
			}
			break;
		default:
			break;
		}
		p = strtok_s(NULL, delim, &ptr);
	}
	return http_flag;
}

//����HTTPͷ����field�ֶΣ����������field�򷵻�true������ȡ����
boolean ParseDate(char* buffer, char* field, char* tempDate) {
	char* p, * ptr, temp[5];
	//const char *field = "If-Modified-Since";
	const char* delim = "\r\n";
	ZeroMemory(temp, 5);
	p = strtok_s(buffer, delim, &ptr);
	printf("%s\n", p);
	int len = strlen(field) + 2;
	while (p) {
		if (strstr(p, field) != NULL) {
			memcpy(tempDate, &p[len], strlen(p) - len);
			//printf("tempDate: %s\n", tempDate);
			return true;
		}
		p = strtok_s(NULL, delim, &ptr);
	}
	return false;
}

//����HTTP������
void makeNewHTTP(char* buffer, char* value) {
	const char* field = "Host";
	const char* newfield = "If-Modified-Since: ";
	//const char *delim = "\r\n";
	char temp[MAXSIZE];
	ZeroMemory(temp, MAXSIZE);
	char* pos = strstr(buffer, field);
	for (int i = 0; i < strlen(pos); i++) {
		temp[i] = pos[i];
	}
	*pos = '\0';
	while (*newfield != '\0') {  //����If-Modified-Since�ֶ�
		*pos++ = *newfield++;
	}
	while (*value != '\0') {
		*pos++ = *value++;
	}
	*pos++ = '\r';
	*pos++ = '\n';
	for (int i = 0; i < strlen(temp); i++) {
		*pos++ = temp[i];
	}
	//printf("buffer: %s\n", buffer);
}

//����url�����ļ���
void makeFilename(char* url, char* filename) {
	//char filename[100];  // �����ļ���
	//ZeroMemory(filename, 100);
	char* p = filename;
	while (*url != '\0') {
		if (*url != '/' && *url != ':' && *url != '.') {
			*p++ = *url;
		}
		url++;
	}
}


//���л���
void makeCache(char* buffer, char* url) {
	char* p, * ptr, num[10], tempBuffer[MAXSIZE + 1];
	const char* delim = "\r\n";
	ZeroMemory(num, 10);
	ZeroMemory(tempBuffer, MAXSIZE + 1);
	memcpy(tempBuffer, buffer, strlen(buffer));//��buffer����д��tempBuffer
	p = strtok_s(tempBuffer, delim, &ptr);//��ȡ��һ��
	memcpy(num, &p[9], 3);
	if (strcmp(num, "200") == 0) {  //״̬����200ʱ����
		//printf("url : %s\n", url);
		char filename[200] = { 0 };  // �����ļ���
		makeFilename(url, filename);
		//printf("filename : %s\n", filename);
		FILE* out;
		if (fopen_s(&out, filename, "wb") == 0) {
			fwrite(buffer, sizeof(char), strlen(buffer), out);
			fclose(out);
		}
		printf("\n�����ѻ��棡\n");
	}
}

//��ȡ����
void getCache(char* buffer, char* filename) {
	char* p, * ptr, num[10], tempBuffer[MAXSIZE + 1];
	const char* delim = "\r\n";
	ZeroMemory(num, 10);
	ZeroMemory(tempBuffer, MAXSIZE + 1);
	memcpy(tempBuffer, buffer, strlen(buffer));
	p = strtok_s(tempBuffer, delim, &ptr);//��ȡ��һ��
	memcpy(num, &p[9], 3);
	if (strcmp(num, "304") == 0) {  //�������صı����е�״̬��Ϊ304ʱ�����ѻ��������
		printf("��ȡ���ػ��棡\n");
		ZeroMemory(buffer, strlen(buffer));
		FILE* in;
		if (fopen_s(&in, filename, "rb") == 0) {
			fread(buffer, sizeof(char), MAXSIZE, in);
			fclose(in);
		}
		needCache = false;
	}
}


//������������Ŀ��������׽��֣�������
bool ConnectToServer(SOCKET* serverSocket, char* host, bool http_flag) {
	SOCKADDR_IN serverAddr;
	serverAddr.sin_family = AF_INET;
	if (http_flag) {
		serverAddr.sin_port = htons(HTTPS_PORT);//https�˿�
	}
	else {
		serverAddr.sin_port = htons(HTTP_PORT); //http80�˿�
	}
	//printf("%s\n", host);
	//�����߳�ʱgethostbyname������
	HOSTENT* hostent = gethostbyname(host);//���ض�Ӧ�ڸ����������İ����������ֺ͵�ַ��Ϣ��hostent�ṹ��ָ��
	if (!hostent) {
		return false;
	}
	IN_ADDR inAddr = *((IN_ADDR*)*hostent->h_addr_list);//�洢32λ��IP��ַ
	serverAddr.sin_addr.S_un.S_addr = inet_addr(inet_ntoa(inAddr));//Ŀ��������׽��ֵ�ַ
	*serverSocket = socket(AF_INET, SOCK_STREAM, 0);//������Ŀ����������ӵ��׽���
	if (*serverSocket == INVALID_SOCKET) {
		return false;
	}
	if (connect(*serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) ==
		SOCKET_ERROR) {
		closesocket(*serverSocket);
		return false;
	}
	return true;

}

//�߳�ִ�к���
unsigned int _stdcall ProxyThread(LPVOID lpParameter) {
	bool http_flag = 0, flag0;//0Ϊhttp��1Ϊhttps
	char Buffer[MAXSIZE], fileBuffer[MAXSIZE];
	char* CacheBuffer, * DateBuffer;
	ZeroMemory(Buffer, MAXSIZE);
	SOCKADDR_IN clientAddr;
	clientAddr.sin_family = AF_INET;
	int length = sizeof(SOCKADDR_IN);
	int recvSize;
	int ret, ret0;
	//���ܿͻ��˵�http����
	recvSize = recv(((ProxyParam*)lpParameter)->cilentSocket, Buffer, MAXSIZE, 0);
	if (recvSize <= 0) {
		goto error;
	}
	HttpHeader* httpHeader;
	httpHeader = new HttpHeader();
	CacheBuffer = new char[recvSize + 1];
	ZeroMemory(CacheBuffer, recvSize + 1);
	memcpy(CacheBuffer, Buffer, recvSize);
	flag0 = ParseHttpHead(CacheBuffer, httpHeader, http_flag);
	http_flag = flag0;

	//��վ����
	for (int i = 0; i < blacklistnum; i++) {
		if (strcmp(httpHeader->url, blacklist[i]) == 1) {
			printf("\n=====================================\n\n");
			printf("����ǰ������վ�ѱ����Σ�\n");
			goto error;
		}
	}

	//�û�����
	//char hostname[128];
	//int retnew;
	//retnew = gethostname(hostname, sizeof(hostname));
	//HOSTENT* hent;
	//hent = gethostbyname(hostname);
	//char* ip;
	//ip = inet_ntoa(*(in_addr*)*hent->h_addr_list);  //��ȡ����ip��ַ
	//if (strcmp(ip, "127.0.0.1") == 1) {
	//	printf("\n=====================================\n\n");
	//	printf("�ͻ�ip��ַ��%s\n", ip);
	//	printf("���������ѱ����Σ�\n");
	//	goto error;
	//}

	//����
	DateBuffer = new char[recvSize + 1];
	ZeroMemory(DateBuffer, strlen(Buffer) + 1);
	memcpy(DateBuffer, Buffer, strlen(Buffer) + 1);
	//printf("DateBuffer: \n%s\n", DateBuffer);
	char filename[200];
	ZeroMemory(filename, 100);
	makeFilename(httpHeader->url, filename);
	//printf("filename : %s\n", filename);
	const char* field;
	field = "Date";
	char date_str[30];  //�����ֶ�Date��ֵ
	ZeroMemory(date_str, 30);
	ZeroMemory(fileBuffer, MAXSIZE);
	FILE* in;
	if (fopen_s(&in, filename, "rb") == 0) {
		printf("\n����������ڸ�url������Ӧ���棡\n");
		fread(fileBuffer, sizeof(char), MAXSIZE, in);
		fclose(in);
		//printf("fileBuffer : \n%s\n", fileBuffer);
		ParseDate(fileBuffer, (char*)field, date_str);
		printf("date_str: %s\n", date_str);
		makeNewHTTP(Buffer, date_str);
		printf("\n======������������======\n%s\n", Buffer);
		haveCache = true;
		goto success;
	}

	//��վ����������
	/*for (int i = 0; i < blacklistnum; i++)
	{
		if (strcmp(httpHeader->url, blacklist[i]) == 1) {
			printf("\n=====================================\n\n");
			printf("����ɹ�������ǰ����%s�ѱ�������http://jwts.hit.edu.cn\n",blacklist[i]);
			memcpy(httpHeader->host, "http://www.ao.fudan.edu.cn/index.html", 22);
		}
	}*/


success:
	if (!ConnectToServer(&((ProxyParam*)lpParameter)->serverSocket, httpHeader->host, http_flag)) {
		printf("��������Ŀ�������ʧ��!\n");
		goto error;
	}
	int ret_s;
	//ret_s = ioctlsocket(((ProxyParam*)lpParameter)->serverSocket, FIONBIO, (unsigned long*)&ul);
	printf("\n\n------*-*------*-*------*-*------*-*------*-*------*-*------*-*------\n\n");
	printf("��������Ŀ������� %s �ɹ�!\n", httpHeader->host);
	if (http_flag == 1) {
		printf("https");
		/*�ж�Ϊhttp���ӻ���https����,���Ϊhttps���ӣ����ؿͻ���Ӧ��*/
		const char* s;
		s = (char*)"HTTP/1.1 200 Connection established\r\n\r\n";
		ret0 = send(((ProxyParam*)lpParameter)->cilentSocket, s, strlen(s) + 1, 0);
		if (ret0 < 0) {
			goto error;
		}
		while (1) {
			recvSize = recv(((ProxyParam*)lpParameter)->cilentSocket, Buffer, MAXSIZE, 0);
			if (recvSize < 0) {
				if (WSAGetLastError() != WSAEWOULDBLOCK) {
					printf("1");
					//printf("errno%d\n", errno);
					goto error;
				}
				else
				{
					continue;
				}
			}
			printf("\n======������======\n%s\n", Buffer);
			//���ͻ��˷��͵�HTTP���ݱ���ֱ��ת����Ŀ�������
				//Sleep(200);
			ret = send(((ProxyParam*)lpParameter)->serverSocket, Buffer, recvSize, 0);
			if (ret < 0) {
				if (WSAGetLastError() != WSAEWOULDBLOCK) {
					printf("2");
					goto error;
				}
				else {
					continue;
				}
			}
			//Sleep(200);
			//�ȴ�Ŀ���������������
			recvSize = recv(((ProxyParam*)lpParameter)->serverSocket, Buffer, MAXSIZE, 0);
			//printf("%s", Buffer);
			printf("%d", recvSize);//����ֵΪ0����ʾ��ʱconnect�Ѿ��رգ�û�н��յ�����
			if (recvSize < 0) {
				if (WSAGetLastError() != WSAEWOULDBLOCK) {
					printf("�������ݱ���ʧ��!\n");
					goto error;
				}
				else {
					continue;
				}

			}
			//�л���ʱ���жϷ��ص�״̬���Ƿ���304�������򽫻�������ݷ��͸��ͻ���
			if (haveCache == true) {
				getCache(Buffer, filename);
			}
			//��Ŀ����������ص�����ֱ��ת�����ͻ���
			printf("\n======��Ӧ����======\n%s\n", Buffer);
			if (needCache == true) {
				makeCache(Buffer, httpHeader->url);  //���汨��
			}
			ret = send(((ProxyParam*)lpParameter)->cilentSocket, Buffer, recvSize, 0);
			if (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
				printf("4");
				goto error;
			}
		}
	}
	printf("\n======������======\n%s\n", Buffer);
	//���ͻ��˷��͵�HTTP���ݱ���ֱ��ת����Ŀ�������
	ret = send(((ProxyParam*)lpParameter)->serverSocket, Buffer, strlen(Buffer) + 1, 0);
	//Sleep(200);
	//�ȴ�Ŀ���������������
	recvSize = recv(((ProxyParam*)lpParameter)->serverSocket, Buffer, MAXSIZE, 0);
	//printf("%s", Buffer);
	printf("%d", recvSize);//����ֵΪ0����ʾ��ʱconnect�Ѿ��رգ�û�н��յ�����
	if (recvSize <= 0) {
		printf("�������ݱ���ʧ��!\n");
		goto error;
	}
	//�л���ʱ���жϷ��ص�״̬���Ƿ���304�������򽫻�������ݷ��͸��ͻ���
	if (haveCache == true) {
		getCache(Buffer, filename);
	}
	//��Ŀ����������ص�����ֱ��ת�����ͻ���
	printf("\n======��Ӧ����======\n%s\n", Buffer);
	if (needCache == true) {
		makeCache(Buffer, httpHeader->url);  //���汨��
	}
	ret = send(((ProxyParam*)lpParameter)->cilentSocket, Buffer, sizeof(Buffer), 0);
	delete CacheBuffer;
	delete DateBuffer;
error:  
	//������
	//printf("�ر��׽���\n");
	Sleep(200);
	int err = WSAGetLastError();
	//printf("error reason %d\n", err);//strerror_s(Buffer,errno)
	closesocket(((ProxyParam*)lpParameter)->cilentSocket);
	closesocket(((ProxyParam*)lpParameter)->serverSocket);
	delete lpParameter;
	_endthreadex(0);
	return 0;
}