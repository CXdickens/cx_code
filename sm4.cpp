#include <stdio.h>
#include <time.h>
#include "sm4_bs.h"

void print_bit(unsigned __int64 x)
{
	__int64 i;
	for(i=0;i<32;i++){printf("%d",(x>>(31-i))&1);if(i%4==3)printf(" ");}printf("\n");
}

void sms4_set_encrypt_key_bs(sms4_key_t_bs *key,unsigned __int64 *user_keyh,unsigned __int64 *user_keyl)
{
	unsigned __int64 Xh[5][4],Xl[5][4],ckh[4],ckl[4];
	unsigned __int64 *RKh,*RKl;

	RKh=&(key->rkh[0][0]);
	RKl=&(key->rkl[0][0]);

	Xh[0][0]=user_keyh[0]^FK_BS00h;
	Xh[0][1]=user_keyh[1]^FK_BS01h;
	Xh[0][2]=user_keyh[2]^FK_BS02h;
	Xh[0][3]=user_keyh[3]^FK_BS03h;
	Xl[0][0]=user_keyl[0]^FK_BS00l;
	Xl[0][1]=user_keyl[1]^FK_BS01l;
	Xl[0][2]=user_keyl[2]^FK_BS02l;
	Xl[0][3]=user_keyl[3]^FK_BS03l;

	Xh[1][0]=user_keyh[4]^FK_BS10h;
	Xh[1][1]=user_keyh[5]^FK_BS11h;
	Xh[1][2]=user_keyh[6]^FK_BS12h;
	Xh[1][3]=user_keyh[7]^FK_BS13h;
	Xl[1][0]=user_keyl[4]^FK_BS10l;
	Xl[1][1]=user_keyl[5]^FK_BS11l;
	Xl[1][2]=user_keyl[6]^FK_BS12l;
	Xl[1][3]=user_keyl[7]^FK_BS13l;

	Xh[2][0]=user_keyh[8 ]^FK_BS20h;
	Xh[2][1]=user_keyh[9 ]^FK_BS21h;
	Xh[2][2]=user_keyh[10]^FK_BS22h;
	Xh[2][3]=user_keyh[11]^FK_BS23h;
	Xl[2][0]=user_keyl[8 ]^FK_BS20l;
	Xl[2][1]=user_keyl[9 ]^FK_BS21l;
	Xl[2][2]=user_keyl[10]^FK_BS22l;
	Xl[2][3]=user_keyl[11]^FK_BS23l;

	Xh[3][0]=user_keyh[12]^FK_BS30h;
	Xh[3][1]=user_keyh[13]^FK_BS31h;
	Xh[3][2]=user_keyh[14]^FK_BS32h;
	Xh[3][3]=user_keyh[15]^FK_BS33h;
	Xl[3][0]=user_keyl[12]^FK_BS30l;
	Xl[3][1]=user_keyl[13]^FK_BS31l;
	Xl[3][2]=user_keyl[14]^FK_BS32l;
	Xl[3][3]=user_keyl[15]^FK_BS33l;

	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,0,0);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,0,1);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS2(Xh,Xl,RKh,RKl,0,2);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS3(Xh,Xl,RKh,RKl,0,3);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS4(Xh,Xl,RKh,RKl,0,4);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,0,5);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,0,6);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS2(Xh,Xl,RKh,RKl,0,7);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS3(Xh,Xl,RKh,RKl,0,8);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS4(Xh,Xl,RKh,RKl,0,9);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,0,10);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,0,11);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS2(Xh,Xl,RKh,RKl,0,12);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS3(Xh,Xl,RKh,RKl,0,13);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS4(Xh,Xl,RKh,RKl,0,14);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,0,15);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,1,0);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS2(Xh,Xl,RKh,RKl,1,1);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS3(Xh,Xl,RKh,RKl,1,2);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS4(Xh,Xl,RKh,RKl,1,3);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,1,4);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,1,5);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS2(Xh,Xl,RKh,RKl,1,6);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS3(Xh,Xl,RKh,RKl,1,7);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS4(Xh,Xl,RKh,RKl,1,8);	
	RKh+=4;RKl+=4;
	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,1,9);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,1,10);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS2(Xh,Xl,RKh,RKl,1,11);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS3(Xh,Xl,RKh,RKl,1,12);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS4(Xh,Xl,RKh,RKl,1,13);	
	RKh+=4;RKl+=4;
	ENC_ROUND_BS0(Xh,Xl,RKh,RKl,1,14);
	RKh+=4;RKl+=4;
	ENC_ROUND_BS1(Xh,Xl,RKh,RKl,1,15);

}
void SMS4_encrypt_bs(sms4_key_t_bs *key,unsigned __int64 *INh,unsigned __int64 *INl,unsigned __int64 *OUTh,unsigned __int64 *OUTl)
{
	unsigned __int64 Xh[5][4],Xl[5][4],ckh[4],ckl[4];
	unsigned __int64 *RKh,*RKl;

	RKh=&(key->rkh[0][0]);
	RKl=&(key->rkl[0][0]);

	Xh[0][0]=INh[0];
	Xh[0][1]=INh[1];
	Xh[0][2]=INh[2];
	Xh[0][3]=INh[3];
	Xl[0][0]=INl[0];
	Xl[0][1]=INl[1];
	Xl[0][2]=INl[2];
	Xl[0][3]=INl[3];

	Xh[1][0]=INh[4];
	Xh[1][1]=INh[5];
	Xh[1][2]=INh[6];
	Xh[1][3]=INh[7];
	Xl[1][0]=INl[4];
	Xl[1][1]=INl[5];
	Xl[1][2]=INl[6];
	Xl[1][3]=INl[7];

	Xh[2][0]=INh[8 ];
	Xh[2][1]=INh[9 ];
	Xh[2][2]=INh[10];
	Xh[2][3]=INh[11];
	Xl[2][0]=INl[8 ];
	Xl[2][1]=INl[9 ];
	Xl[2][2]=INl[10];
	Xl[2][3]=INl[11];

	Xh[3][0]=INh[12];
	Xh[3][1]=INh[13];
	Xh[3][2]=INh[14];
	Xh[3][3]=INh[15];
	Xl[3][0]=INl[12];
	Xl[3][1]=INl[13];
	Xl[3][2]=INl[14];
	Xl[3][3]=INl[15];

	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS2(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS3(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS4(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS2(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS3(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS4(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS2(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS3(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS4(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS2(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS3(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS4(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS2(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS3(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS4(Xh,Xl,RKh,RKl);	
	RKh+=4;RKl+=4;
	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS2(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS3(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS4(Xh,Xl,RKh,RKl);	
	RKh+=4;RKl+=4;
	ROUND_BS0(Xh,Xl,RKh,RKl);
	RKh+=4;RKl+=4;
	ROUND_BS1(Xh,Xl,RKh,RKl);

	OUTh[0]=Xh[0][0];
	OUTh[1]=Xh[0][1];
	OUTh[2]=Xh[0][2];
	OUTh[3]=Xh[0][3];
	OUTl[0]=Xl[0][0];
	OUTl[1]=Xl[0][1];
	OUTl[2]=Xl[0][2];
	OUTl[3]=Xl[0][3];
               
	OUTh[4]=Xh[4][0];
	OUTh[5]=Xh[4][1];
	OUTh[6]=Xh[4][2];
	OUTh[7]=Xh[4][3];
	OUTl[4]=Xl[4][0];
	OUTl[5]=Xl[4][1];
	OUTl[6]=Xl[4][2];
	OUTl[7]=Xl[4][3];

	OUTh[8 ]=Xh[3][0];
	OUTh[9 ]=Xh[3][1];
	OUTh[10]=Xh[3][2];
	OUTh[11]=Xh[3][3];
	OUTl[8 ]=Xl[3][0];
	OUTl[9 ]=Xl[3][1];
	OUTl[10]=Xl[3][2];
	OUTl[11]=Xl[3][3];

	OUTh[12]=Xh[2][0];
	OUTh[13]=Xh[2][1];
	OUTh[14]=Xh[2][2];
	OUTh[15]=Xh[2][3];
	OUTl[12]=Xl[2][0];
	OUTl[13]=Xl[2][1];
	OUTl[14]=Xl[2][2];
	OUTl[15]=Xl[2][3];

}
unsigned __int64 ukeyh[16]={0x0000000000000000,0x2222222222222222,0x4444444444444444,0x6666666666666666,0x8888888888888888,0xAAAAAAAAAAAAAAAA,0xCCCCCCCCCCCCCCCC,0xEEEEEEEEEEEEEEEE,0xFFFFFFFFFFFFFFFF,0xDDDDDDDDDDDDDDDD,0xBBBBBBBBBBBBBBBB,0x9999999999999999,0x7777777777777777,0x5555555555555555,0x3333333333333333,0x1111111111111111};
unsigned __int64 ukeyl[16]={0x1111111111111111,0x3333333333333333,0x5555555555555555,0x7777777777777777,0x9999999999999999,0xBBBBBBBBBBBBBBBB,0xDDDDDDDDDDDDDDDD,0xFFFFFFFFFFFFFFFF,0xEEEEEEEEEEEEEEEE,0xCCCCCCCCCCCCCCCC,0xAAAAAAAAAAAAAAAA,0x8888888888888888,0x6666666666666666,0x4444444444444444,0x2222222222222222,0x0000000000000000};
unsigned __int64 inh[16]={0x0000000000000000,0x2222222222222222,0x4444444444444444,0x6666666666666666,0x8888888888888888,0xAAAAAAAAAAAAAAAA,0xCCCCCCCCCCCCCCCC,0xEEEEEEEEEEEEEEEE,0xFFFFFFFFFFFFFFFF,0xDDDDDDDDDDDDDDDD,0xBBBBBBBBBBBBBBBB,0x9999999999999999,0x7777777777777777,0x5555555555555555,0x3333333333333333,0x1111111111111111};
unsigned __int64 inl[16]={0x1111111111111111,0x3333333333333333,0x5555555555555555,0x7777777777777777,0x9999999999999999,0xBBBBBBBBBBBBBBBB,0xDDDDDDDDDDDDDDDD,0xFFFFFFFFFFFFFFFF,0xEEEEEEEEEEEEEEEE,0xCCCCCCCCCCCCCCCC,0xAAAAAAAAAAAAAAAA,0x8888888888888888,0x6666666666666666,0x4444444444444444,0x2222222222222222,0x0000000000000000};

void main()
{
	clock_t t1,t2;
	unsigned int p; 
	int i,j;
	sms4_key_t_bs keybs;

	printf("pai:\n");
	scanf("%d",&p);
	sms4_set_encrypt_key_bs(&keybs,ukeyh,ukeyl);
	t1 = clock();
	for(i=0;i<p;i++)
	{
		SMS4_encrypt_bs(&keybs,inh,inl,inh,inl);
	}
	t2 = clock();
	printf(" %f %f %f B/s\n",(double)(t2-t1)/CLOCKS_PER_SEC,(16.0*p)/((double)(t2-t1)/CLOCKS_PER_SEC),(16.0*p*16)/((double)(t2-t1)/CLOCKS_PER_SEC));
	for(j=0;j<16;j++){for(i=0;i<16;i++){printf("%x%x,",(unsigned char)(inh[i]>>j*4)&0xf,(unsigned char)(inl[i]>>j*4)&0xf);}printf("\n");}
	//68,1e,df,34,d2,06,96,5e,86,b3,e9,4f,53,6e,42,46,²âÊÔ½á¹û
}