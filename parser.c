#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include <zlib.h>

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define CHUNK 262144
int UncompressData( const unsigned char* abSrc, int nLenSrc, unsigned char* abDst, int nLenDst );

#pragma pack(1)
struct Pkt_FFXIV_chat //0x65001400, 0x67001400
{
	uint8_t unk2[20]; //20..39
	uint32_t id1; //40..43, user ID, constant between sessions/areas
	uint32_t unk3; //44..47, some constant
	uint32_t id2; //48..51, constant between sessions/areas
	uint8_t unk1; //65 needs this, but 67 doesn't... what
	unsigned char name[32];
	unsigned char message[1024];
};
struct Pkt_FFXIV_msg
{
        uint32_t msg_size; //0..3, including size
        uint64_t entity_id; //4..11, variable (changes with area/session, high 4 bits seem constant)
	uint32_t unk1; //12..15
	uint32_t msg_type; //16..19	
	unsigned char *data;
};
struct Pkt_FFXIV
{
	uint8_t unk1[16]; //magic#? Bytes 0-15
	uint64_t timestamp; //unix timestamp, big endian 16-23
	uint32_t size; //Total payload size (including bytes 0-27), big endian, bytes 24-27
	uint8_t unk2[2]; //28-29 
	uint16_t message_count; //Number of messages in payload, big endian, bytes 30-31
	uint8_t flag1; //Unknown, byte 32
	uint8_t flag2; //Compression, byte 33
	uint8_t unk3[6]; //unknown, 34-39
	unsigned char *data; //40+, could be compressed
};
struct Pkt
{
        uint32_t socket;
        uint8_t ip_addr[4];
        uint16_t port; //Little endian
        uint32_t len;
        uint32_t flags;
	struct Pkt_FFXIV data;	
};
#pragma pack()

int main(int argc, char **argv)
{
	FILE *fp = NULL;
	if(--argc)
		fp = fopen(argv[1],"rb");
	else
		fp = fopen("log.bin","rb");
	if(!fp)
		return 1;

	if(argc > 1)
	{
		fseek(fp,atoi(argv[2]),0);
		printf("Seek to 0x%X, %s\n", ftell(fp), argv[2]);
	}

	struct Pkt packet;

	printf("sizeof(Pkt): 0x%X\n", sizeof(struct Pkt));
	printf("sizeof(Pkt_FFXIV): 0x%X\n", sizeof(struct Pkt_FFXIV));

	while(fread(&packet, sizeof(struct Pkt)-sizeof(unsigned char*), 1, fp)) //Read all known data (so Packet and FFXIV packet headers)
	{
		getchar();
		if(!packet.len)
			continue;
		printf("sock: %u\n", packet.socket);
		printf("addr: %u.%u.%u.%u\n", packet.ip_addr[0], packet.ip_addr[1], packet.ip_addr[2], packet.ip_addr[3]);
		printf("port: %u\n", packet.port);
		printf("magn: high %llX low %llX\n", packet.data.unk1, packet.data.unk1[8]);
		printf(" len: %u\n", packet.len);
		printf("flag: %u\n", packet.flags);
		printf("time: %llu\n", packet.data.timestamp);
		printf("size: %u\n", packet.data.size);
		printf("msgc: %u\n", packet.data.message_count);
		printf("flag: %u %u\n", packet.data.flag1, packet.data.flag2);
		if(packet.len < packet.data.size)
			printf("Next set of messages is continuation!\n");

		size_t to_read = packet.len-(sizeof(struct Pkt_FFXIV)-sizeof(unsigned char*)); //Read the remaining messages
		packet.data.data = malloc(to_read);
		fread(packet.data.data, to_read, 1, fp);

		//Decompress stream
		if(packet.data.flag2)
		{
			unsigned char *t_data = malloc(CHUNK);
			UncompressData(packet.data.data,to_read,t_data,CHUNK);
			free(packet.data.data);
			packet.data.data = t_data;
		}
		if(packet.data.size > 18)
		{
			struct Pkt_FFXIV_msg *msg;
			msg = malloc(sizeof(struct Pkt_FFXIV_msg));
			memcpy(msg, packet.data.data, sizeof(struct Pkt_FFXIV_msg)-sizeof(unsigned char*));
			msg->data = packet.data.data + sizeof(struct Pkt_FFXIV_msg) - sizeof(unsigned char*);
			printf("\tsize: 0x%08X %u\n", msg->msg_size, msg->msg_size);
			printf("\t id1: 0x%08llX %llu\n", msg->entity_id, msg->entity_id);
			printf("\ttype: 0x%08X %u\n", msg->msg_type, msg->msg_type);
			if(msg->msg_type == 0x00650014 || msg->msg_type == 0x00670014)
			{
				struct Pkt_FFXIV_chat chat = *(struct Pkt_FFXIV_chat*)(msg->data);
				printf("[%s][%d %d]: %s", chat.name, chat.id1, chat.id2, chat.message);
			}
			free(msg);
		}
		printf("\n------------------\n");
		free(packet.data.data);
		printf("tell: 0x%X\n", ftell(fp));
	}
	fclose(fp);
	return 0;
}

int UncompressData( const unsigned char* abSrc, int nLenSrc, unsigned char* abDst, int nLenDst )
{
    z_stream zInfo ={0};
    zInfo.total_in=  zInfo.avail_in=  nLenSrc;
    zInfo.avail_out= nLenDst;
    zInfo.next_in= (unsigned char*)abSrc;
    zInfo.next_out= abDst;

    int nErr, nRet= -1;
    nErr= inflateInit( &zInfo );               // zlib function
    if ( nErr == Z_OK ) {
        nErr= inflate( &zInfo, Z_FINISH );     // zlib function
        if ( nErr == Z_STREAM_END ) {
            nRet= zInfo.total_out;
        }
    }
    inflateEnd( &zInfo );   // zlib function
    return( nRet ); // -1 or len of output
}
