/*
 * BANK FRAUD DETECTOR - C Web Application
 * Lightweight HTTP server + explainable transaction risk scoring.
 * Educational prototype: rule-based scoring, NOT a trained ML model.
 */
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
typedef SOCKET socket_t;
#define CLOSESOCKET closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCKET close
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEFAULT_PORT 8080
#define BUF_SIZE 16384

static void send_all(socket_t s, const char *data) {
    size_t n = strlen(data), sent = 0;
    while (sent < n) {
        int r = (int)send(s, data + sent, (int)(n - sent), 0);
        if (r <= 0) break;
        sent += (size_t)r;
    }
}
static void response(socket_t s, const char *status, const char *type, const char *body) {
    char head[512];
    snprintf(head, sizeof(head),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        status, type, strlen(body));
    send_all(s, head); send_all(s, body);
}
static void url_decode(char *dst, const char *src, size_t cap) {
    size_t j=0;
    for (size_t i=0; src[i] && j+1<cap; i++) {
        if (src[i]=='+') dst[j++]=' ';
        else if (src[i]=='%' && src[i+1] && src[i+2]) {
            char h[3]={src[i+1],src[i+2],0}; dst[j++]=(char)strtol(h,NULL,16); i+=2;
        } else dst[j++]=src[i];
    }
    dst[j]=0;
}
static double number_field(const char *body, const char *key, double fallback) {
    char needle[80]; snprintf(needle,sizeof(needle),"%s=",key);
    const char *p=strstr(body,needle); if(!p) return fallback;
    p+=strlen(needle); char val[80]; size_t i=0;
    while(p[i] && p[i]!='&' && i<sizeof(val)-1){val[i]=p[i];i++;}
    val[i]=0; char decoded[80]; url_decode(decoded,val,sizeof(decoded));
    return atof(decoded);
}
static int bool_field(const char *body, const char *key) {
    char needle[80]; snprintf(needle,sizeof(needle),"%s=",key);
    const char *p=strstr(body,needle); if(!p) return 0;
    p+=strlen(needle); return (*p=='1' || strncmp(p,"true",4)==0);
}
static void text_field(const char *body, const char *key, char *out, size_t cap, const char *fallback) {
    char needle[80]; snprintf(needle,sizeof(needle),"%s=",key);
    const char *p=strstr(body,needle);
    if(!p){snprintf(out,cap,"%s",fallback);return;}
    p+=strlen(needle); char raw[512]; size_t i=0;
    while(p[i] && p[i]!='&' && i<sizeof(raw)-1){raw[i]=p[i];i++;}
    raw[i]=0; url_decode(out,raw,cap);
}
static void json_escape(const char *in, char *out, size_t cap) {
    size_t j=0; for(size_t i=0;in[i] && j+2<cap;i++){
        if(in[i]=='"' || in[i]=='\\') out[j++]='\\';
        if((unsigned char)in[i]>=32) out[j++]=in[i];
    } out[j]=0;
}
static void analyze(socket_t s, const char *body) {
    double amount=number_field(body,"amount",0);
    double hour=number_field(body,"hour",12);
    double failed=number_field(body,"failed",0);
    double distance=number_field(body,"distance",0);
    int new_device=bool_field(body,"new_device");
    int online=bool_field(body,"online");
    char sender[160], sender_account[80], beneficiary[160], beneficiary_account[80];
    char country[100], currency[12], txn_type[60], channel[60], bank[120];
    char merchant[160], location[160];
    char se[320],sae[160],be[320],bae[160],ce[200],cure[40],te[120],che[120],bke[240],me[320],le[320];
    text_field(body,"sender_name",sender,sizeof(sender),"Unknown sender");
    text_field(body,"sender_account",sender_account,sizeof(sender_account),"Not supplied");
    text_field(body,"beneficiary_name",beneficiary,sizeof(beneficiary),"Unknown beneficiary");
    text_field(body,"beneficiary_account",beneficiary_account,sizeof(beneficiary_account),"Not supplied");
    text_field(body,"country",country,sizeof(country),"India");
    text_field(body,"currency",currency,sizeof(currency),"INR");
    text_field(body,"txn_type",txn_type,sizeof(txn_type),"Bank transfer");
    text_field(body,"channel",channel,sizeof(channel),"Online banking");
    text_field(body,"bank",bank,sizeof(bank),"Not specified");
    text_field(body,"merchant",merchant,sizeof(merchant),"Bank transfer");
    text_field(body,"location",location,sizeof(location),country);
    json_escape(sender,se,sizeof(se)); json_escape(sender_account,sae,sizeof(sae));
    json_escape(beneficiary,be,sizeof(be)); json_escape(beneficiary_account,bae,sizeof(bae));
    json_escape(country,ce,sizeof(ce)); json_escape(currency,cure,sizeof(cure));
    json_escape(txn_type,te,sizeof(te)); json_escape(channel,che,sizeof(che));
    json_escape(bank,bke,sizeof(bke)); json_escape(merchant,me,sizeof(me)); json_escape(location,le,sizeof(le));

    int international=(strcmp(country,"India")!=0 && strcmp(country,"india")!=0);
    int score=0; char reasons[1200]=""; int used=0;
    if(amount>=100000){score+=30; used+=snprintf(reasons+used,sizeof(reasons)-used,"%sVery high transaction amount",used?"; ":"");}
    else if(amount>=50000){score+=20; used+=snprintf(reasons+used,sizeof(reasons)-used,"%sHigh transaction amount",used?"; ":"");}
    else if(amount>=20000){score+=10; used+=snprintf(reasons+used,sizeof(reasons)-used,"%sAbove-normal transaction amount",used?"; ":"");}
    if(international){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sCross-border transaction",used?"; ":"");}
    if(new_device){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sUnrecognized device",used?"; ":"");}
    if(hour<5 || hour>=23){score+=15;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sUnusual transaction hour",used?"; ":"");}
    if(failed>=3){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sMultiple failed attempts",used?"; ":"");}
    else if(failed>=1){score+=8;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sRecent failed attempt(s)",used?"; ":"");}
    if(distance>=500){score+=15;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sUnusual location distance",used?"; ":"");}
    else if(distance>=100){score+=7;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sLocation differs from usual activity",used?"; ":"");}
    if(!online && amount>=20000){score+=5;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sHigh-value in-person transaction",used?"; ":"");}
    if(score>100)score=100;
    const char *risk=score>=60?"HIGH":score>=30?"MEDIUM":"LOW";
    const char *decision=score>=60?"FLAG FOR MANUAL REVIEW":score>=30?"VERIFY CUSTOMER":"APPROVE";
    if(!used)snprintf(reasons,sizeof(reasons),"No major risk indicators detected");
    char out[8192];
    snprintf(out,sizeof(out),
      "{\"ok\":true,\"score\":%d,\"risk\":\"%s\",\"decision\":\"%s\",\"reasons\":\"%s\","
      "\"amount\":%.2f,\"hour\":%.0f,\"failed\":%.0f,\"distance\":%.0f,"
      "\"sender_name\":\"%s\",\"sender_account\":\"%s\",\"beneficiary_name\":\"%s\",\"beneficiary_account\":\"%s\","
      "\"country\":\"%s\",\"currency\":\"%s\",\"txn_type\":\"%s\",\"channel\":\"%s\",\"bank\":\"%s\","
      "\"merchant\":\"%s\",\"location\":\"%s\"}",
      score,risk,decision,reasons,amount,hour,failed,distance,se,sae,be,bae,ce,cure,te,che,bke,me,le);
    response(s,"200 OK","application/json; charset=utf-8",out);
}
static int read_file(const char *path, char *out, size_t cap) {
    FILE *f=fopen(path,"rb"); if(!f)return 0;
    size_t n=fread(out,1,cap-1,f); out[n]=0; fclose(f); return 1;
}

/* Demo transaction stream: represents transactions arriving from an upstream
   banking system. This simulator is for classroom demonstration only. */
static unsigned long stream_id = 1000;
static unsigned int rng_state = 2463534242u;
static unsigned int next_rand(void) {
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 17; rng_state ^= rng_state << 5;
    return rng_state;
}
static void stream_transaction(socket_t s) {
    unsigned int r = next_rand();
    double amounts[] = {450, 1200, 3500, 7800, 12500, 22000, 34000, 68000, 95000, 125000};
    double amount = amounts[r % 10];
    int hour = (int)((r >> 4) % 24);
    int failed = (int)((r >> 9) % 5);
    int distance = (int)((r >> 13) % 950);
    int international = ((r >> 19) % 8 == 0);
    int new_device = ((r >> 22) % 5 == 0);
    int online = ((r >> 25) % 2);
    const char *merchants[] = {"City Mart","QuickPay Store","Metro Electronics","Online Books","Unknown Receiver","Travel Desk"};
    const char *locations[] = {"Kollam, Kerala","Kochi, Kerala","Bengaluru, India","Dubai, UAE","Chennai, India"};
    const char *merchant = merchants[(r >> 3) % 6];
    const char *location = locations[(r >> 7) % 5];
    int score=0; char reasons[512]=""; int used=0;
    if(amount>=100000){score+=30;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sVery high transaction amount",used?"; ":"");}
    else if(amount>=50000){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sHigh transaction amount",used?"; ":"");}
    else if(amount>=20000){score+=10;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sAbove-normal transaction amount",used?"; ":"");}
    if(international){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sInternational transaction",used?"; ":"");}
    if(new_device){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sUnrecognized device",used?"; ":"");}
    if(hour<5 || hour>=23){score+=15;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sUnusual transaction hour",used?"; ":"");}
    if(failed>=3){score+=20;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sMultiple failed attempts",used?"; ":"");}
    else if(failed>=1){score+=8;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sRecent failed attempt(s)",used?"; ":"");}
    if(distance>=500){score+=15;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sUnusual location distance",used?"; ":"");}
    else if(distance>=100){score+=7;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sLocation differs from usual activity",used?"; ":"");}
    if(!online && amount>=20000){score+=5;used+=snprintf(reasons+used,sizeof(reasons)-used,"%sHigh-value in-person transaction",used?"; ":"");}
    if(score>100)score=100;
    const char *risk=score>=60?"HIGH":score>=30?"MEDIUM":"LOW";
    const char *decision=score>=60?"BLOCK / MANUAL REVIEW":score>=30?"VERIFY CUSTOMER":"APPROVE";
    if(!used)snprintf(reasons,sizeof(reasons),"No major risk indicators detected");
    char out[2048];
    snprintf(out,sizeof(out),
      "{\"ok\":true,\"id\":\"TXN-%lu\",\"score\":%d,\"risk\":\"%s\",\"decision\":\"%s\","
      "\"reasons\":\"%s\",\"amount\":%.2f,\"hour\":%d,\"failed\":%d,\"distance\":%d,"
      "\"international\":%s,\"new_device\":%s,\"merchant\":\"%s\",\"location\":\"%s\"}",
      ++stream_id,score,risk,decision,reasons,amount,hour,failed,distance,
      international?"true":"false",new_device?"true":"false",merchant,location);
    response(s,"200 OK","application/json; charset=utf-8",out);
}


#define QUEUE_MAX 200
static char transaction_queue[QUEUE_MAX][4096];
static int queue_head=0, queue_tail=0, queue_count=0;
static unsigned long queue_id=5000;
static int enqueue_transaction(const char *body) {
    if(queue_count>=QUEUE_MAX) return 0;
    snprintf(transaction_queue[queue_tail],sizeof(transaction_queue[queue_tail]),"%s",body);
    queue_tail=(queue_tail+1)%QUEUE_MAX; queue_count++; queue_id++; return 1;
}
static int dequeue_transaction(char *out,size_t cap) {
    if(queue_count<=0) return 0;
    snprintf(out,cap,"%s",transaction_queue[queue_head]);
    queue_head=(queue_head+1)%QUEUE_MAX; queue_count--; return 1;
}
static void queue_status(socket_t s) {
    char out[256];
    snprintf(out,sizeof(out),"{\"ok\":true,\"queued\":%d,\"capacity\":%d}",queue_count,QUEUE_MAX);
    response(s,"200 OK","application/json; charset=utf-8",out);
}
static void submit_transaction(socket_t s,const char *body) {
    if(!enqueue_transaction(body)){response(s,"429 Too Many Requests","application/json","{\"ok\":false,\"error\":\"Queue is full. Process pending transactions first.\"}");return;}
    char out[256]; snprintf(out,sizeof(out),"{\"ok\":true,\"message\":\"Transaction submitted to analysis queue\",\"queued\":%d}",queue_count);
    response(s,"202 Accepted","application/json; charset=utf-8",out);
}
static void process_next_transaction(socket_t s) {
    char body[4096];
    if(!dequeue_transaction(body,sizeof(body))){
        response(s,"200 OK","application/json; charset=utf-8","{\"ok\":true,\"empty\":true,\"message\":\"No pending transactions\"}");
        return;
    }
    analyze(s,body);
}

static void handle(socket_t client) {
    char req[BUF_SIZE]; int n=(int)recv(client,req,sizeof(req)-1,0);
    if(n<=0)return; req[n]=0;
    char method[8]="", path[256]=""; sscanf(req,"%7s %255s",method,path);
    if(strcmp(method,"OPTIONS")==0){response(client,"204 No Content","text/plain","");return;}
    if(strcmp(path,"/api/health")==0){
        response(client,"200 OK","application/json","{\"ok\":true,\"service\":\"Bank Fraud Detector C Server\"}");return;
    }
    if(strcmp(path,"/api/stream")==0 && strcmp(method,"GET")==0){ stream_transaction(client); return; }
    if(strcmp(path,"/api/queue")==0 && strcmp(method,"GET")==0){ queue_status(client); return; }
    if(strcmp(path,"/api/submit")==0 && strcmp(method,"POST")==0){
        char *body=strstr(req,"\r\n\r\n"); if(!body){response(client,"400 Bad Request","application/json","{\"ok\":false,\"error\":\"Missing request body\"}");return;}
        body+=4; submit_transaction(client,body); return;
    }
    if(strcmp(path,"/api/process-next")==0 && strcmp(method,"POST")==0){ process_next_transaction(client); return; }
    if(strcmp(path,"/api/analyze")==0 && strcmp(method,"POST")==0){
        char *body=strstr(req,"\r\n\r\n"); if(!body){response(client,"400 Bad Request","application/json","{\"ok\":false,\"error\":\"Missing request body\"}");return;}
        body+=4; analyze(client,body); return;
    }
    if(strcmp(path,"/")==0 || strcmp(path,"/index.html")==0 || strcmp(path,"/generator")==0 || strcmp(path,"/generator.html")==0 || strcmp(path,"/analyzer")==0 || strcmp(path,"/analyzer.html")==0){
        char html[30000];
        const char *file=(strcmp(path,"/generator")==0 || strcmp(path,"/generator.html")==0)?"public/generator.html":
                         (strcmp(path,"/analyzer")==0 || strcmp(path,"/analyzer.html")==0)?"public/analyzer.html":"public/index.html";
        if(read_file(file,html,sizeof(html))) response(client,"200 OK","text/html; charset=utf-8",html);
        else response(client,"500 Internal Server Error","text/plain","Could not find public/index.html. Run the server from the project folder.");
        return;
    }
    response(client,"404 Not Found","text/plain","404 - Not found");
}
int main(void) {
    int port = DEFAULT_PORT;
    const char *port_env = getenv("PORT");
    if (port_env && *port_env) { int parsed = atoi(port_env); if (parsed > 0 && parsed < 65536) port = parsed; }
#ifdef _WIN32
    WSADATA wsa; if(WSAStartup(MAKEWORD(2,2),&wsa)!=0){puts("Winsock initialization failed.");return 1;}
#endif
    socket_t server=socket(AF_INET,SOCK_STREAM,0);
    if(server==INVALID_SOCKET){puts("Could not create server socket.");return 1;}
    int opt=1;
#ifdef _WIN32
    setsockopt(server,SOL_SOCKET,SO_REUSEADDR,(const char*)&opt,sizeof(opt));
#else
    setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
#endif
    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons((unsigned short)port);
    if(bind(server,(struct sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR || listen(server,10)==SOCKET_ERROR){
        printf("Could not bind to port %d.\n", port); CLOSESOCKET(server); return 1;
    }
    printf("\n  BANK FRAUD DETECTOR - C WEB APP\n  --------------------------------\n  Listening on port %d\n  Press Ctrl+C to stop the server.\n\n",port);
    for(;;){socket_t client=accept(server,NULL,NULL);if(client!=INVALID_SOCKET){handle(client);CLOSESOCKET(client);}}
    CLOSESOCKET(server);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
