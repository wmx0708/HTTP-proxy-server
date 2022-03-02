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

//黑名单
const char* blacklist[10] = { "mail.hit.edu.cn / ","yzb.buaa.edu.cn / ","hituc.hit.edu.cn / " };
int blacklistnum = 3;

//http头部
struct HttpHeader {
	char method[4];
	char url[1024];
	char host[1024];
	char cookie[1024 * 10];
	HttpHeader() {
		ZeroMemory(this, sizeof(HttpHeader));
	}
};
bool InitSocket();//scoket初始化
void ParseHttpHead(char* buffer, HttpHeader* httpHeader);//解析http头
boolean ParseDate(char* buffer, char* field, char* tempDate);
void makeNewHTTP(char* buffer, char* value);
void makeFilename(char* url, char* filename);
void makeCache(char* buffer, char* url);
void getCache(char* buffer, char* filename);
bool ConnectToServer(SOCKET* serverSocket, char* host);
unsigned int _stdcall ProxyThread(LPVOID lpParameter);
//代理服务器参数
SOCKET ProxyServer;//服务器套接字用于监听
SOCKADDR_IN ProxyServerAddr;//套接字地址
const int ProxyPort = 10240;//代理服务器端口

bool haveCache = false;
bool needCache = true;

struct ProxyParam {
	SOCKET cilentSocket;
	SOCKET serverSocket;
};
unsigned long ul = 1;
int main(int argc, TCHAR* argv[]) {
	printf("代理服务器正在启动\n");
	printf("初始化...\n");
	if (!InitSocket()) {
		printf("服务器初始化失败\n");
		return -1;
	}
	printf("代理服务器正在运行，监听 : %d\n", ProxyPort);
	SOCKET acceptSocket = INVALID_SOCKET;
	ProxyParam* lpProxyParam;
	HANDLE hThread;//声明线程句柄
	DWORD dwThreadID;//线程ID
	//代理服务器循环监听
	while (true) {
		haveCache = false;
		needCache = true;
		acceptSocket = accept(ProxyServer, NULL, NULL);//接收客户端的请求
		lpProxyParam = new ProxyParam;
		if (lpProxyParam == NULL) {
			continue;
		}
		lpProxyParam->cilentSocket = acceptSocket;//服务器返回给客户端的连接套接字
		hThread = (HANDLE)_beginthreadex(NULL, 0, &ProxyThread, (LPVOID)lpProxyParam, 0, 0);//创建线程
		CloseHandle(hThread);//归还线程句柄资源
		Sleep(200);
	}
	closesocket(ProxyServer);//关闭本次套接字
	WSACleanup();
	return 0;
}

//初始化套接字
bool InitSocket() {
	//加载套接字库（必须）
	WORD wVersionRequested;
	WSADATA wsaData;
	int err; ////套接字加载时错误提示
	wVersionRequested = MAKEWORD(2, 2); //版本是2.2
										//加载dll文件Socket库
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {//找不到winsock.dll
		printf("加载winsock.dll失败，错误：%d", WSAGetLastError());
		return false;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		printf("不能找到正确的winsock版本\n");
		WSACleanup();
		return false;
	}
	ProxyServer = socket(AF_INET, SOCK_STREAM, 0); //创建TCP连接的套接字
	if (INVALID_SOCKET == ProxyServer) {
		printf("创建套接字失败，错误代码为 %d\n", WSAGetLastError());
		return false;
	}
	ProxyServerAddr.sin_family = AF_INET;
	ProxyServerAddr.sin_port = htons(ProxyPort); //指向代理服务器的端口
	ProxyServerAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//0.0.0.0INADDR_ANY
	if (bind(ProxyServer, (SOCKADDR*)&ProxyServerAddr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		printf("绑定套接字失败\n");
		return false;
	}
	if (listen(ProxyServer, SOMAXCONN) == SOCKET_ERROR) {
		printf("监听端口%d失败", ProxyPort);
		return false;
	}
	return true;
}

//解析TCP报文中的HTTP头部
bool ParseHttpHead(char* buffer, HttpHeader* httpHeader, bool http_flag) {
	char* p;
	char* ptr;
	const char* delim = "\r\n";
	//将存储在buffer中的http头字符串分割
	p = strtok_s(buffer, delim, &ptr);
	printf("%s\n", p);
	if (p[0] == 'G') {  //GET方式
		memcpy(httpHeader->method, "GET", 3);
		memcpy(httpHeader->url, &p[4], strlen(p) - 13);  //url的长度
	}
	else if (p[0] == 'P') {  //POST方式
		memcpy(httpHeader->method, "POST", 4);
		memcpy(httpHeader->url, &p[5], strlen(p) - 14);
	}
	//printf("%s\n", httpHeader->url);
	p = strtok_s(NULL, delim, &ptr);//delim="/r/n"
	while (p) {
		switch (p[0]) {
		case 'H':  //host
			//判断域名是否含有“：443”端口样式，相比普通的http域名，https头的域名会多加“：443”字样
			if (strstr(p, (char*)":443"))
			{
				http_flag = 1;
				memcpy(httpHeader->host, &p[6], strlen(p) - 10);//相比http多减去4个字节“：443”
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

//分析HTTP头部的field字段，如果包含该field则返回true，并获取日期
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

//改造HTTP请求报文
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
	while (*newfield != '\0') {  //插入If-Modified-Since字段
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

//根据url构造文件名
void makeFilename(char* url, char* filename) {
	//char filename[100];  // 构造文件名
	//ZeroMemory(filename, 100);
	char* p = filename;
	while (*url != '\0') {
		if (*url != '/' && *url != ':' && *url != '.') {
			*p++ = *url;
		}
		url++;
	}
}


//进行缓存
void makeCache(char* buffer, char* url) {
	char* p, * ptr, num[10], tempBuffer[MAXSIZE + 1];
	const char* delim = "\r\n";
	ZeroMemory(num, 10);
	ZeroMemory(tempBuffer, MAXSIZE + 1);
	memcpy(tempBuffer, buffer, strlen(buffer));//将buffer内容写进tempBuffer
	p = strtok_s(tempBuffer, delim, &ptr);//提取第一行
	memcpy(num, &p[9], 3);
	if (strcmp(num, "200") == 0) {  //状态码是200时缓存
		//printf("url : %s\n", url);
		char filename[200] = { 0 };  // 构造文件名
		makeFilename(url, filename);
		//printf("filename : %s\n", filename);
		FILE* out;
		if (fopen_s(&out, filename, "wb") == 0) {
			fwrite(buffer, sizeof(char), strlen(buffer), out);
			fclose(out);
		}
		printf("\n报文已缓存！\n");
	}
}

//获取缓存
void getCache(char* buffer, char* filename) {
	char* p, * ptr, num[10], tempBuffer[MAXSIZE + 1];
	const char* delim = "\r\n";
	ZeroMemory(num, 10);
	ZeroMemory(tempBuffer, MAXSIZE + 1);
	memcpy(tempBuffer, buffer, strlen(buffer));
	p = strtok_s(tempBuffer, delim, &ptr);//提取第一行
	memcpy(num, &p[9], 3);
	if (strcmp(num, "304") == 0) {  //主机返回的报文中的状态码为304时返回已缓存的内容
		printf("获取本地缓存！\n");
		ZeroMemory(buffer, strlen(buffer));
		FILE* in;
		if (fopen_s(&in, filename, "rb") == 0) {
			fread(buffer, sizeof(char), MAXSIZE, in);
			fclose(in);
		}
		needCache = false;
	}
}


//根据主机创建目标服务器套接字，并连接
bool ConnectToServer(SOCKET* serverSocket, char* host, bool http_flag) {
	SOCKADDR_IN serverAddr;
	serverAddr.sin_family = AF_INET;
	if (http_flag) {
		serverAddr.sin_port = htons(HTTPS_PORT);//https端口
	}
	else {
		serverAddr.sin_port = htons(HTTP_PORT); //http80端口
	}
	//printf("%s\n", host);
	//当多线程时gethostbyname易阻塞
	HOSTENT* hostent = gethostbyname(host);//返回对应于给定主机名的包含主机名字和地址信息的hostent结构的指针
	if (!hostent) {
		return false;
	}
	IN_ADDR inAddr = *((IN_ADDR*)*hostent->h_addr_list);//存储32位的IP地址
	serverAddr.sin_addr.S_un.S_addr = inet_addr(inet_ntoa(inAddr));//目标服务器套接字地址
	*serverSocket = socket(AF_INET, SOCK_STREAM, 0);//创建与目标服务器连接的套接字
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

//线程执行函数
unsigned int _stdcall ProxyThread(LPVOID lpParameter) {
	bool http_flag = 0, flag0;//0为http，1为https
	char Buffer[MAXSIZE], fileBuffer[MAXSIZE];
	char* CacheBuffer, * DateBuffer;
	ZeroMemory(Buffer, MAXSIZE);
	SOCKADDR_IN clientAddr;
	clientAddr.sin_family = AF_INET;
	int length = sizeof(SOCKADDR_IN);
	int recvSize;
	int ret, ret0;
	//接受客户端的http请求
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

	//网站屏蔽
	for (int i = 0; i < blacklistnum; i++) {
		if (strcmp(httpHeader->url, blacklist[i]) == 1) {
			printf("\n=====================================\n\n");
			printf("您所前往的网站已被屏蔽！\n");
			goto error;
		}
	}

	//用户过滤
	//char hostname[128];
	//int retnew;
	//retnew = gethostname(hostname, sizeof(hostname));
	//HOSTENT* hent;
	//hent = gethostbyname(hostname);
	//char* ip;
	//ip = inet_ntoa(*(in_addr*)*hent->h_addr_list);  //获取本地ip地址
	//if (strcmp(ip, "127.0.0.1") == 1) {
	//	printf("\n=====================================\n\n");
	//	printf("客户ip地址：%s\n", ip);
	//	printf("您的主机已被屏蔽！\n");
	//	goto error;
	//}

	//缓存
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
	char date_str[30];  //保存字段Date的值
	ZeroMemory(date_str, 30);
	ZeroMemory(fileBuffer, MAXSIZE);
	FILE* in;
	if (fopen_s(&in, filename, "rb") == 0) {
		printf("\n代理服务器在该url下有相应缓存！\n");
		fread(fileBuffer, sizeof(char), MAXSIZE, in);
		fclose(in);
		//printf("fileBuffer : \n%s\n", fileBuffer);
		ParseDate(fileBuffer, (char*)field, date_str);
		printf("date_str: %s\n", date_str);
		makeNewHTTP(Buffer, date_str);
		printf("\n======改造后的请求报文======\n%s\n", Buffer);
		haveCache = true;
		goto success;
	}

	//网站引导：钓鱼
	/*for (int i = 0; i < blacklistnum; i++)
	{
		if (strcmp(httpHeader->url, blacklist[i]) == 1) {
			printf("\n=====================================\n\n");
			printf("钓鱼成功：您所前往的%s已被引导至http://jwts.hit.edu.cn\n",blacklist[i]);
			memcpy(httpHeader->host, "http://www.ao.fudan.edu.cn/index.html", 22);
		}
	}*/


success:
	if (!ConnectToServer(&((ProxyParam*)lpParameter)->serverSocket, httpHeader->host, http_flag)) {
		printf("代理连接目标服务器失败!\n");
		goto error;
	}
	int ret_s;
	//ret_s = ioctlsocket(((ProxyParam*)lpParameter)->serverSocket, FIONBIO, (unsigned long*)&ul);
	printf("\n\n------*-*------*-*------*-*------*-*------*-*------*-*------*-*------\n\n");
	printf("代理连接目标服务器 %s 成功!\n", httpHeader->host);
	if (http_flag == 1) {
		printf("https");
		/*判断为http连接还是https连接,如果为https连接，返回客户端应答*/
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
			printf("\n======请求报文======\n%s\n", Buffer);
			//将客户端发送的HTTP数据报文直接转发给目标服务器
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
			//等待目标服务器返回数据
			recvSize = recv(((ProxyParam*)lpParameter)->serverSocket, Buffer, MAXSIZE, 0);
			//printf("%s", Buffer);
			printf("%d", recvSize);//返回值为0，表示此时connect已经关闭，没有接收到数据
			if (recvSize < 0) {
				if (WSAGetLastError() != WSAEWOULDBLOCK) {
					printf("接收数据报文失败!\n");
					goto error;
				}
				else {
					continue;
				}

			}
			//有缓存时，判断返回的状态码是否是304，若是则将缓存的内容发送给客户端
			if (haveCache == true) {
				getCache(Buffer, filename);
			}
			//将目标服务器返回的数据直接转发给客户端
			printf("\n======响应报文======\n%s\n", Buffer);
			if (needCache == true) {
				makeCache(Buffer, httpHeader->url);  //缓存报文
			}
			ret = send(((ProxyParam*)lpParameter)->cilentSocket, Buffer, recvSize, 0);
			if (ret < 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
				printf("4");
				goto error;
			}
		}
	}
	printf("\n======请求报文======\n%s\n", Buffer);
	//将客户端发送的HTTP数据报文直接转发给目标服务器
	ret = send(((ProxyParam*)lpParameter)->serverSocket, Buffer, strlen(Buffer) + 1, 0);
	//Sleep(200);
	//等待目标服务器返回数据
	recvSize = recv(((ProxyParam*)lpParameter)->serverSocket, Buffer, MAXSIZE, 0);
	//printf("%s", Buffer);
	printf("%d", recvSize);//返回值为0，表示此时connect已经关闭，没有接收到数据
	if (recvSize <= 0) {
		printf("接收数据报文失败!\n");
		goto error;
	}
	//有缓存时，判断返回的状态码是否是304，若是则将缓存的内容发送给客户端
	if (haveCache == true) {
		getCache(Buffer, filename);
	}
	//将目标服务器返回的数据直接转发给客户端
	printf("\n======响应报文======\n%s\n", Buffer);
	if (needCache == true) {
		makeCache(Buffer, httpHeader->url);  //缓存报文
	}
	ret = send(((ProxyParam*)lpParameter)->cilentSocket, Buffer, sizeof(Buffer), 0);
	delete CacheBuffer;
	delete DateBuffer;
error:  
	//错误处理
	//printf("关闭套接字\n");
	Sleep(200);
	int err = WSAGetLastError();
	//printf("error reason %d\n", err);//strerror_s(Buffer,errno)
	closesocket(((ProxyParam*)lpParameter)->cilentSocket);
	closesocket(((ProxyParam*)lpParameter)->serverSocket);
	delete lpParameter;
	_endthreadex(0);
	return 0;
}