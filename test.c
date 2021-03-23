//test_malloc_stats.c
#include<stdio.h>
#include<stdlib.h>
 
int func1();
 
int main()
{
	char *p=NULL;
	p=(char *)malloc(100);
	if(!p){
		printf("In main ,malloc fail\n");
		return -1;
	}
	printf("********before call func1 **********\n");
	malloc_stats();//在要执行内存检测的函数之前打印内存信息
	
	func1();
	printf("\n@@@@@@@@after call func1 @@@@@@@@@@@\n");
	malloc_stats();//在要执行内存检测的函数之后打印内存信息
	free(p);
	return 1;
	
}
 
int func1(void)//申请1024字节，但没有释放，有内存泄露
{
	char *p=NULL;
	p=(char *)malloc(1024);//func1函数申请1024字节
	if(!p)
	{
		printf("Malloc error\n");
	}
	return 0;
}
