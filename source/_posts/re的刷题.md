---
title: re的刷题
date: 2020-05-12 14:22:47
tags: buuctf
categories: 
- ctf
- re
---
教练我想学逆向
<!-- more -->

## day1    5.5

### easyre

拖进ida，shift+F12查找flag

>   IDA Pro:交互式反汇编器，是典型的递归下降反汇编器。
>
>   导航条:
>       蓝色 表示常规的指令函数
>       黑色 节与节之间的间隙
>       银白色 数据内容
>       粉色 表示外部导入符号
>       暗黄色 表示ida未识别的内容
>
>   IDA主界面:
>       IDA View三种反汇编视图:文本视图、图表视图、路径视图
>       Hex View 十六进制窗口
>       Imports 导入函数窗口
>       Struceures 结构体窗口
>       Exports 导出函数窗口
>       Enums 枚举窗口
>       Strings 字符串窗口
>
>   常用功能及快捷键:
>       空格键:切换文本视图与图表视图
>       ESC:返回上一个操作地址
>       G:搜索地址和符号
>       N:对符号进行重命名
>       冒号键:常规注释 
>       分号键:可重复注释
>       Alt+M:添加标签
>       Ctrl+M:查看标签
>       Ctrl+S:查看段的信息
>       代码数据切换
>       C-->代码/D-->数据/A-->ascii字符串/U-->解析成未定义的内容
>       X:查看交叉应用
>       F5:查看伪代码
>       Alt+T:搜索文本
>       Alt+B:搜索十六进制
>    
>   导入jni.h分析jni库函数。
>    
>   伪C代码窗口:
>       右键
>       comment-注释伪c代码。
>       copy to -assembly-把伪c代码复制到反汇编窗口的汇编代码。
>    
>   IDA可以修改so的hex来修改so，edit，然后edit-patchrogram，
>   在这里建议使用winhex来实现。
>   ————————————————
>   版权声明：本文为CSDN博主「阿鲁巴110」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
>   原文链接：https://blog.csdn.net/qq_30531517/java/article/details/82559428



### reverse1

查找flag找到

aThisIsTheRight db 'this is the right flag!',0Ah,0

接下来寻找什么时候调用的

~~~
loc_140011948:                          ; CODE XREF: sub_1400118C0+61j
.text:0000000140011948                 lea     rcx, aInputTheFlag ; "input the flag:"
.text:000000014001194F                 call    sub_1400111D1
.text:0000000140011954                 lea     rdx, [rbp+130h+Str1]
.text:0000000140011958                 lea     rcx, a20s       ; "%20s"
.text:000000014001195F                 call    sub_14001128F
.text:0000000140011964                 lea     rcx, Str2       ; "{hello_world}"
.text:000000014001196B                 call    j_strlen
.text:0000000140011970                 mov     r8, rax         ; MaxCount
.text:0000000140011973                 lea     rdx, Str2       ; "{hello_world}"
.text:000000014001197A                 lea     rcx, [rbp+130h+Str1] ; Str1
.text:000000014001197E                 call    cs:strncmp
.text:0000000140011984                 test    eax, eax
.text:0000000140011986                 jz      short loc_140011996
.text:0000000140011988                 lea     rcx, aWrongFlag ; "wrong flag\n"
.text:000000014001198F                 call    sub_1400111D1
.text:0000000140011994                 jmp     short loc_1400119A2
.text:0000000140011996 ; ---------------------------------------------------------------------------
.text:0000000140011996
.text:0000000140011996 loc_140011996:                          ; CODE XREF: sub_1400118C0+C6j
.text:0000000140011996                 lea     rcx, aThisIsTheRight ; "this is the right flag!\n"
~~~

第一次：hello_world，错误。

>   1，所用的寄存器不同于32下的eax,ebx,ecx,edx,esi,edi,esp,ebp等，在64位下是rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp,此外又增加了r8,r9,r10,r11,r12,r13,r14,r15等寄存器。但eax,ax,ah,al等依然可用，且增加了spl,bpl等8位寄存器调用，r8等也可以用r8d,r8w,r8b进行32位，16位，8位的调用。
>   2，函数调用参数传递不同于32下的stdcall规范，而采用fastcall，前四个参数为别放入rcx,rdx,r8,r9四个寄存器中，并在堆栈中留出4*8=32个字节的空间，多于四个的参数放入堆栈。
>   3，函数调用后，由调用者负责堆栈回收。

伪代码

~~~c
int sub_1400118C0()
{
  char *v0; // rdi@1
  signed __int64 i; // rcx@1
  size_t v2; // rax@5
  size_t v3; // rax@9
  char v5; // [sp+0h] [bp-20h]@1
  signed int v6; // [sp+20h] [bp+0h]@4
  char Str1; // [sp+48h] [bp+28h]@9
  unsigned __int64 v8; // [sp+128h] [bp+108h]@5
  unsigned __int64 v9; // [sp+130h] [bp+110h]@4

  v0 = &v5;
  for ( i = 82i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  v9 = (unsigned __int64)&v6 ^ _security_cookie;
  for ( *(&v6 + 1) = 0; ; ++*(&v6 + 1) )
  {
    v8 = *(&v6 + 1);
    v2 = j_strlen(Str2);
    if ( v8 > v2 )
      break;
    if ( Str2[(signed __int64)*(&v6 + 1)] == 111 )
      Str2[(signed __int64)*(&v6 + 1)] = 48;
  }
  sub_1400111D1("input the flag:");
  sub_14001128F("%20s", &Str1);
  v3 = j_strlen(Str2);
  if ( !strncmp(&Str1, Str2, v3) )
    sub_1400111D1("this is the right flag!\n");
  else
    sub_1400111D1("wrong flag\n");
  sub_14001113B(&v5, &unk_140019D00);
  return sub_1400112E9((unsigned __int64)&v6 ^ v9);
}
~~~

>   strncmp函数为字符串比较函数，字符串大小的比较是以ASCII 码表上的顺序来决定，此顺序亦为字符的值。其函数声明为int strncmp ( const char * str1, const char * str2, size_t n );功能是把 str1 和 str2 进行比较，最多比较前 **n** 个字节，若str1与str2的前n个字符相同，则返回0；若s1大于s2，则返回大于0的值；若s1 小于s2，则返回小于0的值。

111为o，48为0，把str2字符串的o变成0

lea ----取内存单元的有效知地址指令，只用于传送地道址。

ptr-----是临时的类型转换，相当于C语言中的强制类型转换

![](D:%5Cstudy%5C%E7%9E%8C%E7%9D%A1%E8%99%AB-%E5%AE%89%E5%85%A8%5C%E9%A2%98%E7%9B%AE%5Cre%5Creverse1%5CSnipaste_2020-05-05_20-15-53.png)



### reserve2

~~~
.data:0000000000601080 ; char flag
.data:0000000000601080 flag            db 7Bh                  ; DATA XREF: main+34r
.data:0000000000601080                                         ; main+44r ...
.data:0000000000601081 aHacking_for_fu db 'hacking_for_fun}',0
.data:0000000000601081 _data           ends
~~~

flag：hacking_for_fun}

伪代码

~~~ c
  pid = fork();
  if ( pid )
  {
    argv = (const char **)&stat_loc;
    waitpid(pid, &stat_loc, 0);
  }
  else
  {
    for ( i = 0; i <= strlen(&flag); ++i )
    {
      if ( *(&flag + i) == 105 || *(&flag + i) == 114 )
        *(&flag + i) = 49;
    }
  }
  printf("input the flag:", argv);
  __isoc99_scanf(4196628LL, &s2);
  if ( !strcmp(&flag, &s2) )
    result = puts("this is the right flag!");
  else
    result = puts("wrong flag!");
  v4 = *MK_FP(__FS__, 40LL) ^ v9;
  return result;
}
~~~

105：i，114：r，49：1

试一试hack1ng_fo1_fun，起飞。

版本不兼容，后来点了以兼容模式运行

### 新年快乐

打开有点不对

>
>   UPX是一个著名的压缩壳,主要功能是压缩PE文件(比如exe,dll等文件),有时候也可能被病毒用于免杀.壳upx是一种保护程序。一般是EXE文件的一种外保护措施，主要用途 ：
>
>
>   1、让正规文件被保护起来，不容易被修改和破解。
>
>
>   2、使文件压缩变小。
>
>
>   3、保护杀毒软件安装程序，使之不受病毒侵害。
>
>   4、木马，病毒的保护外壳，使之难以为攻破。 
>
>   +   技术原理
>
>
>   对于可执行程序资源压缩,是保护文件的常用手段. 俗称加壳,加壳过的程序可以直接运行,但是不能查看源代码.要经过脱壳才可以查看源代码.
>
>
>   加壳：其实是利用特殊的算法，对EXE、DLL文件里的资源进行压缩。类似WINZIP的效果，只不过这个压缩之后的文件，可以独立运行，解压过程完全隐蔽，都在内存中完成。解压原理，是加壳工具在文件头里加了一段指令，告诉CPU，怎么才能解压自己。当加壳时，其实就是给可执行的文件加上个外衣。用户执行的只是这个外壳程序。当执行这个程序的时候这个壳就会把原来的程序在内存中解开，解开后，以后的就交给真正的程序。
>
>   +   加壳脱壳
>
>   程序为了反跟踪、被人跟踪调试、防止算法程序被别人静态分析就需要加壳。使用加壳软件加密代码和数据，就可以保护你程序数据的完整性，防止被程序修改和被窥视内幕。
>   https://blog.csdn.net/dubuqingfenggzy/java/article/details/16881607

![Snipaste_2020-05-05_21-14-01](%E6%96%B0%E5%B9%B4%E5%BF%AB%E4%B9%90/Snipaste_2020-05-05_21-14-01.png)

![](%E6%96%B0%E5%B9%B4%E5%BF%AB%E4%B9%90/Snipaste_2020-05-05_21-13-47.png)

![](%E6%96%B0%E5%B9%B4%E5%BF%AB%E4%B9%90/Snipaste_2020-05-05_21-26-53.png)

![](%E6%96%B0%E5%B9%B4%E5%BF%AB%E4%B9%90/Snipaste_2020-05-05_21-28-08.png)

happly new year!

## day2    5.6

### helloworld

apk文件。

>   APK是Android操作系统使用的一种应用程序包文件格式，基于 ZIP 文件格式。

我用jadx打开。



### 内涵软件

![](%E5%86%85%E6%B6%B5%E8%BD%AF%E4%BB%B6/Snipaste_2020-05-06_19-15-27.png)

~~~c
  v3 = (int)"DBAPP{49d3c93df25caad81232130f3d2ebfad}";
  while ( v4 >= 0 )
  {
    printf("距离出现答案还有%d秒，请耐心等待！\n", v4);
    sub_40100A();
    --v4;
  }
  printf("\n\n\n这里本来应该是答案的,但是粗心的程序员忘记把变量写进来了,你要不逆向试试看:(Y/N)\n");
  v2 = 1;
  scanf("%c", &v2);
  if ( v2 == 89 )
  {
    printf("OD吾爱破解或者IDA这些逆向软件都挺好的！");
    result = sub_40100A();
  }
~~~

内涵

### xor

我傻了，没注意64位。

伪代码，v7是输入且33位异或后==global

~~~c
printf("Input your flag:\n", 0LL);
  get_line(v7, 256LL);
  if ( strlen(v7) != 33 )
    goto LABEL_13;
  for ( i = 1; i < 33; ++i )
    v7[i] ^= v7[i - 1];
  v3 = (signed __int64)global;
  if ( !strncmp(v7, global, 0x21uLL) )
    printf("Success", v3);
~~~

~~~
aFKWO_@XZUPFVMD 
db 'f',0Ah              
; DATA XREF: __data:_globalo
db 'k',0Ch,'w&O.@',11h,'x',0Dh,'Z;U',11h,'p',19h,'F',1Fh,'v"M#D',0Eh,'g',6,'h',0Fh,'G2O',0
~~~

~~~python
a=['f', 'k',0xC,'w&O.@',0x11,'x',0xD,'Z;U',0x11,'p',0x19,'F',0x1F,'v"M#D',0x0E,'g',6,'h',0xF,'G2O',0]
#print(len(a))
#print(type(a[2]))
for i in range(len(a)):
    if type(a[i]).__name__ == 'int':
        a[i]=chr(a[i])
print(a)
a="".join(a)
#print(len(a))
flag='f'
for i in range(1,33):
    flag+=chr(ord(a[i])^ord(a[i-1]))
print(flag)
~~~

写的脚本有点问题，得到fg{QianQiuWanDai_YiTongJiangHu}O，应该是flag{QianQiuWanDai_YiTongJiangHu}

### guessgame

~~~
lea     rax, aBjdS1mple_rev3 ; "BJD{S1mple_ReV3r5e_W1th_0D_0r_IDA}"
~~~

签到题



### reserve_3

输入flag

~~~c
 sub_41132F("please enter the flag:", v4);
 sub_411375("%20s", (unsigned int)&Str);
 v0 = j_strlen(&Str);
 v1 = (const char *)sub_4110BE(&Str, v0, &v11);
 strncpy(Dest, v1, 0x28u);
 sub_411127();
 i = j_strlen(Dest);
 for ( j = 0; (signed int)j < (signed int)i; ++j )
    Dest[j] += j;
 v2 = j_strlen(Dest);
 strncmp(Dest, Str2, v2);
 if ( sub_411127() )
    sub_41132F("wrong flag!\n", v4);
 else
    sub_41132F("rigth flag!\n", v4);
 sub_41126C(&savedregs, &dword_415890);
~~~

sub_41132F输出，sub_411375输入。输入str经过sub_4110BE变成v1，变成Dest，dest里循环加j，0<j<len(dest),比较str2。

找str2

~~~
push    offset Str2     ; "e3nifIH9b_C@n@dH"
~~~

~~~python
a="e3nifIH9b_C@n@dH"
flag=""
for i in range(len(a)):
    flag+=chr(ord(a[i])-i )
print(flag)

~~~

结果：e2lfbDB2ZV95b3V9，错误。忘了还有sub_4110BE。sub_411AB0

~~~c
if ( i == 1 )
        {
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[(signed int)(unsigned __int8)byte_41A144[0] >> 2];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[((byte_41A144[1] & 0xF0) >> 4) | 16 * (byte_41A144[0] & 3)];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[64];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[64];
        }
        else if ( v4 == 2 )
        {
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[(signed int)(unsigned __int8)byte_41A144[0] >> 2];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[((byte_41A144[1] & 0xF0) >> 4) | 16 * (byte_41A144[0] & 3)];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[((byte_41A144[2] & 0xC0) >> 6) | 4 * (byte_41A144[1] & 0xF)];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[64];
        }
        else if ( v4 == 3 )
        {
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[(signed int)(unsigned __int8)byte_41A144[0] >> 2];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[((byte_41A144[1] & 0xF0) >> 4) | 16 * (byte_41A144[0] & 3)];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[((byte_41A144[2] & 0xC0) >> 6) | 4 * (byte_41A144[1] & 0xF)];
          *((_BYTE *)Dst + v5++) = aAbcdefghijklmn[byte_41A144[2] & 0x3F];
        }
      }
~~~

~~~
mov     cl, byte ptr ds:aAbcdefghijklmn[edx] ; "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"...
~~~

base64,emmmmmmmmm~~





## day3    5.7

### 不一样的flag

看到提示我觉得不妙，会不会f5不能用了。

![](%E4%B8%8D%E4%B8%80%E6%A0%B7%E7%9A%84flag/Snipaste_2020-05-07_20-35-40.png)

搜索flag。

call    _puts应该是输出ptr，call    _printf

~~~c
while ( 1 )
  {
    puts("you can choose one action to execute");
    puts("1 up");
    puts("2 down");
    puts("3 left");
    printf("4 right\n:");
    scanf("%d", &v3);
    if ( v3 == 2 )
    {
      ++v1;
    }
    else if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        --v2;
      }
      else
      {
        if ( v3 != 4 )
           LABEL_13:
          exit(1);
        ++v2;
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      --v1;
    }
    for ( i = 0; i <= 1; ++i )
    {
      if ( *(&v1 + i) < 0 || *(&v1 + i) > 4 )
        exit(1);
    }
    if ( *((_BYTE *)&v5 + 5 * v1 + v2 - 41) == 49 )
      exit(1);
    if ( *((_BYTE *)&v5 + 5 * v1 + v2 - 41) == 35 )
    {
      puts("\nok, the order you enter is the flag!");
      exit(0);
    }
  }
~~~

v3=1,v1--;

v3=2,v1++;

v3=3,v2--;

v3=4,v2++;

v5+5*v1+v2-41=35('#')!=49('1')

~~~c
char v0; // [sp+17h] [bp-35h]@1
qmemcpy(&v0, _data_start__, 0x19u);
~~~

~~~c
mov     ebx, offset __data_start__ ; "*11110100001010000101111#"
~~~

想多了，这是一个迷宫

```
*1111
01000
01010
00010
1111#
```

相当于二维数组，v1v2是坐标，1是可以走的，*头#尾。



### 刮开有奖

挂不了，生气。

~~~c
GetDlgItemTextA(hDlg, 1000, &String, 0xFFFF);
      if ( strlen(&String) == 8 )
      {
        v7 = 90;
        v8 = 74;
        v9 = 83;
        v10 = 69;
        v11 = 67;
        v12 = 97;
        v13 = 78;
        v14 = 72;
        v15 = 51;
        v16 = 110;
        v17 = 103;
        sub_4010F0(&v7, 0, 10);
        memset(&v26, 0, 0xFFFFu);
        v26 = v23;
        v28 = v25;
        v27 = v24;
        v4 = (const char *)sub_401000(&v26, strlen(&v26));
        memset(&v26, 0, 0xFFFFu);
        v27 = v21;
        v26 = v20;
        v28 = v22;
        v5 = (const char *)sub_401000(&v26, strlen(&v26));
        if ( String == v7 + 34
          && v19 == v11
          && 4 * v20 - 141 == 3 * v9
          && v21 / 4 == 2 * (v14 / 9)
          && !strcmp(v4, "ak1w")
          && !strcmp(v5, "V1Ax") )
          MessageBoxA(hDlg, "U g3t 1T!", "@_@", 0);
      }
~~~

看看sub_4010F0对v7-v17做了什么

~~~c
int __cdecl sub_4010F0(int a1, int a2, int a3)
{
  int result; // eax@1
  int i; // esi@1
  int v5; // ecx@2
  int v6; // edx@2

  result = a3;
  for ( i = a2; i <= a3; a2 = i )
  {
    v5 = 4 * i;
    v6 = *(_DWORD *)(4 * i + a1);
    if ( a2 < result && i < result )
    {
      do
      {
        if ( v6 > *(_DWORD *)(a1 + 4 * result) )
        {
          if ( i >= result )
            break;
          ++i;
          *(_DWORD *)(v5 + a1) = *(_DWORD *)(a1 + 4 * result);
          if ( i >= result )
            break;
          while ( *(_DWORD *)(a1 + 4 * i) <= v6 )
          {
            ++i;
            if ( i >= result )
              goto LABEL_13;
          }
          if ( i >= result )
            break;
          v5 = 4 * i;
          *(_DWORD *)(a1 + 4 * result) = *(_DWORD *)(4 * i + a1);
        }
        --result;
      }
      while ( i < result );
    }
LABEL_13:
    *(_DWORD *)(a1 + 4 * result) = v6;
    sub_4010F0(a1, a2, i - 1);
    result = a3;
    ++i;
  }
  return result;
}
~~~

~~~c
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
using namespace std;

int sub(char *a1, int a2, int a3)
{
  int result; // eax@1
  int i; // esi@1
  int v5; // ecx@2
  int v6; // edx@2

  result = a3;
  for ( i = a2; i <= a3; a2 = i )
  {
    v5 = 4 * i;
    v6 = a1[4 * i];
    if ( a2 < result && i < result )
    {
      do
      {
        if ( v6 > a1[4 * result] )
        {
          if ( i >= result )
            break;
          ++i;
          a1[v5] = a1[4 * result];

          if ( i >= result )
            break;
          while ( a1[4 * i] <= v6 )
          {
            ++i;
            if ( i >= result )
              goto LABEL_13;
          }
          if ( i >= result )
            break;
          v5 = 4 * i;
          a1 [4 * result] = a1[4 * i];
        }
        --result;
      }while ( i < result );
    }
LABEL_13:
    a1 [4 * result] = v6;
    sub(a1, a2, i - 1);
    result = a3;
    ++i;
  }
  return result;
}
int main(){
    char a1[11]={90,74,83,69,67,97,78,72,51,110,103};
    sub(a1,0,10);
    for(int i=0;i<=10;i++)
        cout<<a1[i];

return 0;
}

~~~

JSE aNH ng

淦，我的汇编就是一坨屎

去掉4*。

>   淦，我的保存没了。

string是flag，其中(v4, "ak1w")(v5, "V1Ax")是base64结果。

string = “UJWP1jMp”



## day4    5.8

### simpleRev

64位。

48-57:0-9

65-90：A-Z

97-122：a-z

Decry()里

~~~c
__int64 Decry()
{
  char v1; // [sp+Fh] [bp-51h]@19
  int v2; // [sp+10h] [bp-50h]@1
  signed int v3; // [sp+14h] [bp-4Ch]@1
  signed int i; // [sp+18h] [bp-48h]@1
  signed int v5; // [sp+1Ch] [bp-44h]@1
  char src[8]; // [sp+20h] [bp-40h]@1
  __int64 v7; // [sp+28h] [bp-38h]@1
  int v8; // [sp+30h] [bp-30h]@1
  __int64 v9; // [sp+40h] [bp-20h]@1
  __int64 v10; // [sp+48h] [bp-18h]@1
  int v11; // [sp+50h] [bp-10h]@1
  __int64 v12; // [sp+58h] [bp-8h]@1

  v12 = *MK_FP(__FS__, 40LL);
  *(_QWORD *)src = 357761762382LL;
  v7 = 0LL;
  v8 = 0;
  v9 = 512969957736LL;
  v10 = 0LL;
  v11 = 0;
  text = join(key3, (const char *)&v9);
  strcpy(key, key1);
  strcat(key, src);
  v2 = 0;
  v3 = 0;
  getchar();
  v5 = strlen(key);
  for ( i = 0; i < v5; ++i )
  {
    if ( key[v3 % v5] > 64 && key[v3 % v5] <= 90 )
      key[i] = key[v3 % v5] + 32;
    ++v3;
  }
  printf("Please input your flag:", src);
  while ( 1 )
  {
    v1 = getchar();
    if ( v1 == 10 )
      break;
    if ( v1 == 32 )
    {
      ++v2;
    }
    else
    {
      if ( v1 <= 96 || v1 > 122 )
      {
        if ( v1 > 64 && v1 <= 90 )
          str2[v2] = (v1 - 39 - key[v3++ % v5] + 97) % 26 + 97;
      }
      else
      {
        str2[v2] = (v1 - 39 - key[v3++ % v5] + 97) % 26 + 97;
      }
      if ( !(v3 % v5) )
        putchar(32);
      ++v2;
    }
  }
  if ( !strcmp(text, str2) )
    puts("Congratulation!\n");
  else
    puts("Try again!\n");
  return *MK_FP(__FS__, 40LL) ^ v12;
}
~~~

~~~c
char *__fastcall join(const char *a1, const char *a2)
{
  size_t v2; // rbx@1
  size_t v3; // rax@1
  char *dest; // [sp+18h] [bp-18h]@1

  v2 = strlen(a1);
  v3 = strlen(a2);
  dest = (char *)malloc(v2 + v3 + 1);
  if ( !dest )
    exit(1);
  strcpy(dest, a1);
  strcat(dest, a2);
  return dest;
}
~~~

join就是字符串相连

主要变量：

v9 = 512969957736LL;==hadow

*(_QWORD *)src = 357761762382LL;==NDCLS

>   ~~~c
>   int main(){
>       long long a = 512969957736LL;
>       char buffer[100];
>       sprintf(buffer, "%lld", a);
>       printf("%s\n", buffer);
>       const char *b=(const char *)&a;
>       cout<<b;
>       return 0;
>   }
>   
>   ~~~

text = join(key3, (const char *)&v9);

key3       ; "kills"

key1       ; "ADSFK"



过程：

key=key1+src 

//text=killshadow，key=ADSFKNDCLS

key变小写

//keyt=adsfkndcls

str2变换

最后str2=test

str2[v3] = (v2 - 39 - key[v4++ % v6] + 97) % 26 + 97;

~~~python
key="adsfkndcls"
text="killshadow"
str2=""
flag=""
import string
print(len(key))
v4 = 9
for i in range(0,10):
    for j in range(65,91):
        zm = chr((j - 39 - ord(key[(v4+1) % 10]) + 97) % 26 + 97)
        if zm==text[i]:
            flag+=chr(j)
            v4=v4+1
            break
print(flag)

~~~

### java逆向解密

~~~java
package defpackage;

import java.util.ArrayList;
import java.util.Scanner;

/* renamed from: Reverse  reason: default package */
public class Reverse {
    public static void main(String[] args) {
        Scanner s = new Scanner(System.in);
        System.out.println("Please input the flag ：");
        String str = s.next();
        System.out.println("Your input is ：");
        System.out.println(str);
        Encrypt(str.toCharArray());
    }

    public static void Encrypt(char[] arr) {
        ArrayList<Integer> Resultlist = new ArrayList<>();
        for (char c : arr) {
            Resultlist.add(Integer.valueOf((c + '@') ^ 32));
        }
        int[] KEY = {180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65};
        ArrayList<Integer> KEYList = new ArrayList<>();
        for (int valueOf : KEY) {
            KEYList.add(Integer.valueOf(valueOf));
        }
        System.out.println("Result:");
        if (Resultlist.equals(KEYList)) {
            System.out.println("Congratulations！");
        } else {
            System.err.println("Error！");
        }
    }
}
~~~

(flag+@)^32==key

~~~python
KEY = [180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65]
flag=""
for i in range(0,len(KEY)):
    for j in range(32,127):
        if (j+ord('@'))^32==KEY[i]:
            flag+=chr(j)
print(flag)

~~~

芜湖！！！

### findit

~~~java
public class MainActivity extends ActionBarActivity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_main);
        final EditText edit = (EditText) findViewById(R.id.widget2);
        final TextView text = (TextView) findViewById(R.id.widget1);
        final char[] a = {'T', 'h', 'i', 's', 'I', 's', 'T', 'h', 'e', 'F', 'l', 'a', 'g', 'H', 'o', 'm', 'e'};
        final char[] b = {'p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6', '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p', '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}'};
        ((Button) findViewById(R.id.widget3)).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                char[] x = new char[17];
                char[] y = new char[38];
                for (int i = 0; i < 17; i++) {
                    if ((a[i] < 'I' && a[i] >= 'A') || (a[i] < 'i' && a[i] >= 'a')) {
                        x[i] = (char) (a[i] + 18);
                    } else if ((a[i] < 'A' || a[i] > 'Z') && (a[i] < 'a' || a[i] > 'z')) {
                        x[i] = a[i];
                    } else {
                        x[i] = (char) (a[i] - 8);
                    }
                }
                if (String.valueOf(x).equals(edit.getText().toString())) {
                    for (int i2 = 0; i2 < 38; i2++) {
                        if ((b[i2] < 'A' || b[i2] > 'Z') && (b[i2] < 'a' || b[i2] > 'z')) {
                            y[i2] = b[i2];
                        } else {
                            y[i2] = (char) (b[i2] + 16);
                            if ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {
                                y[i2] = (char) (y[i2] - 26);
                            }
                        }
                    }
                    text.setText(String.valueOf(y));
                    return;
                }
                text.setText("答案错了肿么办。。。不给你又不好意思。。。哎呀好纠结啊~~~");
            }
        });
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
~~~

b变y，y是flag

~~~java
for (int i2 = 0; i2 < 38; i2++) {
	if ((b[i2] < 'A' || b[i2] > 'Z') && (b[i2] < 'a' || b[i2] > 'z')) {
		y[i2] = b[i2];
	} else {
		y[i2] = (char) (b[i2] + 16);
		if ((y[i2] > 'Z' && y[i2] < 'a') || y[i2] >= 'z') {
			y[i2] = (char) (y[i2] - 26);
		}
	}
}
~~~

凯撒，16位。我不管，爆破

![](findit/Snipaste_2020-05-08_20-38-41.png)

pvkq{m164675262033l4m49lnp7p9mnk28k75}

### 8086

迷~~

~~~
db 0B9h, 22h, 0, 8Dh, 1Eh, 2 dup(0), 8Bh, 0F9h, 4Fh, 80h
db 31h, 1Fh, 0E2h, 0F8h, 8Dh, 16h, 2 dup(0), 0B4h, 9, 0CDh
db 21h, 0C3h
~~~

c强制转换代码

~~~
mov     cx, 22h ; '"'
lea     bx, aUDuT@Z@wj__Q@g ; "]U[du~|t@{z@wj.}.~q@gjz{z@wzqW~/b;"
loc_10039:                              ; CODE XREF: seg001:000Fj
mov     di, cx
dec     di
xor     byte ptr [bx+di], 1Fh
loop    loc_10039
lea     dx, aUDuT@Z@wj__Q@g ; "]U[du~|t@{z@wj.}.~q@gjz{z@wzqW~/b;"
mov     ah, 9
int     21h             ; DOS - PRINT STRING; DS:DX -> string terminated by "$"
retn
~~~

~~~
xor     byte ptr [bx+di], 1Fh
~~~

~~~python
a="]U[du~|t@{z@wj.}.~q@gjz{z@wzqW~/b;"
flag=""
b=0x1f
print(b)

for i in range(len(a)):
    flag+=chr(ord(a[i])^b)
print(flag)

~~~

### rsa

public key：MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMAzLFxkrkcYL2wch21CM2kQVFpY9+7+./AvKr1rzQczdAgMBAAE=

http://tool.chacuo.net/cryptrsakeyparse

| key长度： | 256                                                          |
| --------- | ------------------------------------------------------------ |
| 模数：    | C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD |
| 指数：    | 65537 (0x10001)                                              |

86934482296048119190666062003494800588905656017203025617216654058378322103517

p=285960468890451637935629440372639283459

q=304008741604601924494328155975272418463

~~~
openssl rsa -pubin -text -modulus -in pub.txt
python2 rsatool.py -o private.pem -e 65537 -p 285960468890451637935629440372639283459 -q 304008741604601924494328155975272418463
openssl rsautl -decrypt -in flag.enc -inkey private.pem
~~~

~~~python
#coding=utf-8
import math
import sys
from Crypto.PublicKey import RSA
arsa=RSA.generate(1024)
arsa.p=
arsa.q=
arsa.e=
arsa.n=arsa.p*arsa.q
Fn=long((arsa.p-1)*(arsa.q-1))
i=1
while(True):
    x=(Fn*i)+1
    if(x%arsa.e==0):
           arsa.d=x/arsa.e
           break
    i=i+1
private=open('private.pem','w')
private.write(arsa.exportKey())
private.close()
~~~



## day5    5.9

### CrackRTF

32位

~~~c
printf("pls input the first passwd(1): ");
  scanf("%s", &pbData);
  if ( strlen((const char *)&pbData) != 6 )
  {
    printf("Must be 6 characters!\n");
    ExitProcess(0);
  }
~~~

pw6位

~~~
v5 = unknown_libname_1((char *)&pbData);
  if ( v5 < 100000 )
    ExitProcess(0);
  strcat((char *)&pbData, "@DBApp");
~~~

~~~
__int32 __cdecl unknown_libname_1(char *a1)
{
  return atol(a1);
}
~~~

pw>100000

~~~c
strcat((char *)&pbData, "@DBApp");
v0 = strlen((const char *)&pbData);
~~~

pbData=pw+"@DBApp"

v0=12

~~~c
sub_40100A(&pbData, v0, &String1);
~~~

好像hash

去搜CryptCreateHash

[CryptCreateHash:ALG_ID](#https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash)

sha1

~~~python
import hashlib
data="@DBApp"
a="6E32D0943418C2C33385BC35A1470250DD8923A9"
for i in range(100000,1000000):
    print(i)
    flag=str(i)+data
    sha1 = (hashlib.sha1(flag).hexdigest()).upper()
    if sha1==a:
        print(flag)
        break
~~~

跑了好久。。。。

pw=123321@DBApp

~~~
if ( !_strcmpi(&String1, "6E32D0943418C2C33385BC35A1470250DD8923A9") )
  {
    printf("continue...\n\n");
    printf("pls input the first passwd(2): ");
    memset(&String, 0, 0x104u);
    scanf("%s", &String);
    if ( strlen(&String) != 6 )
    {
      printf("Must be 6 characters!\n");
      ExitProcess(0);
    }
    strcat(&String, (const char *)&pbData);
    memset(&String1, 0, 0x104u);
    v1 = strlen(&String);
    sub_401019((BYTE *)&String, v1, &String1);
    if ( !_strcmpi("27019e688a4e62a649fd99cadaafdb4e", &String1) )
    {
      if ( !(unsigned __int8)sub_40100F(&String) )
      {
        printf("Error!!\n");
        ExitProcess(0);
      }
      printf("bye ~~\n");
    }
  }
~~~

~~~c
strcat(&String, (const char *)&pbData);
    memset(&String1, 0, 0x104u);
    v1 = strlen(&String);
    sub_401019((BYTE *)&String, v1, &String1);
    if ( !_strcmpi("27019e688a4e62a649fd99cadaafdb4e", &String1) )
~~~

string=pw2+"123321@DBApp"

CryptCreateHash里0x8003u是MD5，查不到。

会不会还是数字，爆破数字。

~~~python
import hashlib
data="123321@DBApp"
a="27019e688a4e62a649fd99cadaafdb4e"
md5 = hashlib.md5()
for i in range(100000,1000000):
    print(i)
    flag=str(i)+data
    md5.update(flag)
    if md5==a:
        print(flag)
        break
~~~

无

看后面吧

~~~c
hResInfo = FindResourceA(0, (LPCSTR)0x65, "AAA");
  if ( hResInfo )
  {
    nNumberOfBytesToWrite = SizeofResource(0, hResInfo);
    hResData = LoadResource(0, hResInfo);
    if ( hResData )
    {
      lpBuffer = LockResource(hResData);
      sub_401005(lpString, (int)lpBuffer, nNumberOfBytesToWrite);
      hFile = CreateFileA("dbapp.rtf", 0x10000000u, 0, 0, 2u, 0x80u, 0);
~~~

到这里，

sub_401019((BYTE *)&String, v1, &String1);

函数sub_401040(BYTE *pbData, DWORD dwDataLen, LPSTR lpString1)

~~~c
 memset(&v4, 0xCCu, 0x4Cu);
  v7 = lstrlenA(lpString);
  v6 = lpString;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a3 )
      break;
    *(_BYTE *)(i + a2) ^= v6[i % v7];
  }
~~~

发现lpString进行了异或，a2为lpString首地址。

AAA是啥？我受不了了了，看wp。

{\rtf1\ansi\

。。。。。。。。。。。就这样吧，累了



## day6    5.10

### 注册器

~~~
char[] x = "dd2940c04462b4dd7c450528835cca15".toCharArray();
                    x[2] = (char) ((x[2] + x[3]) - 50);
                    x[4] = (char) ((x[2] + x[5]) - 48);
                    x[30] = (char) ((x[31] + x[9]) - 48);
                    x[14] = (char) ((x[27] + x[28]) - 97);
                    for (int i = 0; i < 16; i++) {
                        char a = x[31 - i];
                        x[31 - i] = x[i];
                        x[i] = a;
                    }

~~~

~~~python
x="dd2940c04462b4dd7c450528835cca15"
b=list(x)
print(b)
b[2] = chr((ord(b[2]) + ord(b[3])) - 50)
b[4] = chr((ord(b[2]) + ord(b[5])) - 48)
b[30] = chr((ord(b[31]) + ord(b[9])) - 48)
b[14] = chr((ord(b[27]) + ord(b[28])) - 97)
for i in range(16):
        a = b[31 - i];
        b[31 - i] = b[i];
        b[i] = a;


print(''.join(b))

~~~

### luck_guy

~~~
int __fastcall patch_me(int a1)
{
  int result; // eax@2

  if ( ((((unsigned int)((unsigned __int64)a1 >> 32) >> 31) + (_BYTE)a1) & 1)
     - ((unsigned int)((unsigned __int64)a1 >> 32) >> 31) == 1 )
    result = puts("just finished");
  else
    result = get_flag();
  return result;
}
~~~

a1最后一位为0

flag=f1+f2

~~~
.text:0000000000400845 loc_400845:                             ; DATA XREF: .rodata:0000000000400BC8o
.text:0000000000400845                 mov     edi, offset aOkItSFlag ; "OK, it's flag:"
.text:000000000040084A                 call    _puts
.text:000000000040084F                 lea     rax, [rbp+s]
.text:0000000000400853                 mov     edx, 28h        ; n
.text:0000000000400858                 mov     esi, 0          ; c
.text:000000000040085D                 mov     rdi, rax        ; s
.text:0000000000400860                 call    _memset
.text:0000000000400865                 lea     rax, [rbp+s]
.text:0000000000400869                 mov     esi, offset f1  ; "GXY{do_not_"
.text:000000000040086E                 mov     rdi, rax        ; dest
.text:0000000000400871                 call    _strcat
.text:0000000000400876                 lea     rax, [rbp+s]
.text:000000000040087A                 mov     esi, offset f2  ; src
.text:000000000040087F                 mov     rdi, rax        ; dest
.text:0000000000400882                 call    _strcat
.text:0000000000400887                 lea     rax, [rbp+s]
.text:000000000040088B                 mov     rsi, rax
.text:000000000040088E                 mov     edi, offset format ; "%s"
.text:0000000000400893                 mov     eax, 0
.text:0000000000400898                 call    _printf
.text:000000000040089D                 jmp     loc_400975
~~~

f2=i c u g ` o f 

~~~
.text:00000000004008CA loc_4008CA:                             ; DATA XREF: .rodata:0000000000400BE0o
.text:00000000004008CA                 mov     [rbp+s], 0
.text:00000000004008D2                 mov     [rbp+var_28], 0
.text:00000000004008D6                 mov     byte ptr [rbp+s], 69h
.text:00000000004008DA                 mov     byte ptr [rbp+s+1], 63h
.text:00000000004008DE                 mov     byte ptr [rbp+s+2], 75h
.text:00000000004008E2                 mov     byte ptr [rbp+s+3], 67h
.text:00000000004008E6                 mov     byte ptr [rbp+s+4], 60h
.text:00000000004008EA                 mov     byte ptr [rbp+s+5], 6Fh
.text:00000000004008EE                 mov     byte ptr [rbp+s+6], 66h
.text:00000000004008F2                 mov     byte ptr [rbp+s+7], 7Fh
.text:00000000004008F6                 lea     rax, [rbp+s]
.text:00000000004008FA                 mov     rsi, rax        ; src
.text:00000000004008FD                 mov     edi, offset f2  ; dest
.text:0000000000400902                 call    _strcat
.text:0000000000400907                 jmp     short loc_400975
~~~

~~~
.text:0000000000400963 loc_400963:                             ; CODE XREF: get_flag+145j
.text:0000000000400963                 cmp     [rbp+var_38], 7
.text:0000000000400967                 jle     short loc_400912
.text:0000000000400969                 jmp     short loc_400975
~~~

~~~
.text:0000000000400912 loc_400912:                             ; CODE XREF: get_flag+19Cj
.text:0000000000400912                 mov     eax, [rbp+var_38]
.text:0000000000400915                 cdq
.text:0000000000400916                 shr     edx, 1Fh
.text:0000000000400919                 add     eax, edx
.text:000000000040091B                 and     eax, 1
.text:000000000040091E                 sub     eax, edx
.text:0000000000400920                 cmp     eax, 1
.text:0000000000400923                 jnz     short loc_400943
.text:0000000000400925                 mov     eax, [rbp+var_38]
.text:0000000000400928                 cdqe
.text:000000000040092A                 movzx   eax, ds:f2[rax]
.text:0000000000400931                 sub     eax, 2
.text:0000000000400934                 mov     edx, eax
.text:0000000000400936                 mov     eax, [rbp+var_38]
.text:0000000000400939                 cdqe
.text:000000000040093B                 mov     ds:f2[rax], dl
.text:0000000000400941                 jmp     short loc_40095F
~~~

>   CDQ 是一个让很多人感到困惑的指令。  这个指令把 EAX 的第 31 bit 复制到 EDX 的每一个 bit 上。 它大多出现在除法运算之前。它实际的作用只是把EDX的所有位都设成EAX最高位的值。也就是说，当EAX <80000000, EDX 为00000000；当EAX >= 80000000， EDX 则为FFFFFFFF。

我的f5和wp不一样，只能看汇编。头疼

~~~python
f2=[0x69,0x63,0x75,0x67,0x60,0x6f,0x66,0x7f]
flag = 'GXY{do_not_'

for j in range(8):
    if ( j % 2 == 1 ):
        flag+= chr(f2[j] - 2)
    else:
        flag+= chr(f2[j] -1)
    
print(flag)

~~~

### younger_drive

脱壳，32位。

v0是printf返回值，为1008

sub_41116D(&v5 == &v5, v0);

没看出什么

v1=12

v2=flag

~~~c
int __usercall sub_411E30@<eax>(char a1@<zf>, int result@<eax>)
{
  int v2; // ST18_4@2
  int _0; // [sp+0h] [bp+0h]@2

  if ( !a1 )
  {
    v2 = result;
    sub_4111F9(_0, 0);
    result = v2;
  }
  return result;
}
~~~

[堆栈平衡看看](https://www.cnblogs.com/ajiannet/archive/2007/04/20/721679.html)

## day7    5.11

### pyre

>   pyc文件是python编译后的字节码文件。
>   在python中，输入一个模块相对来说是一个比较费时的事情，所以Python做了一些技巧，以便使输入模块更加快一些。一种方法是创建字节编译的文件，这些文件以.pyc作为扩展名。
>   当你在下次从别的程序输入这个模块的时候，.pyc文件是十分有用的——它会快得多，因为一部分输入模块所需的处理已经完成了。
>   在你import别的py文件时(也就是模块)，那个py文件会被存一份pyc文件以加速下次装载。而主文件因为只需要装载一次就没有存pyc。

![](pyre/Snipaste_2020-05-11_17-10-58.png)

https://tool.lu/pyc/

~~~python
print 'Welcome to Re World!'
print 'Your input1 is your flag~'
l = len(input1)
for i in range(l):
    num = ((input1[i] + i) % 128 + 128) % 128
    code += num

for i in range(l - 1):
    code[i] = code[i] ^ code[i + 1]

print code
code = [
    '\x1f',
    '\x12',
    '\x1d',
    '(',
    '0',
    '4',
    '\x01',
    '\x06',
    '\x14',
    '4',
    ',',
    '\x1b',
    'U',
    '?',
    'o',
    '6',
    '*',
    ':',
    '\x01',
    'D',
    ';',
    '%',
    '\x13']

~~~

~~~python
input1=''
code = ['\x1f', '\x12', '\x1d', '(', '0', '4', '\x01', '\x06', '\x14', '4', ',', '\x1b', 'U', '?', 'o', '6', '*', ':', '\x01', 'D', ';', '%', '\x13']
I=len(code)
print(ord(code[0]))
for i in range(I-2,-1,-1):
    code[i]=chr(ord(code[i])^ord(code[i+1]))
print(code)

for i in range(I):
    input1+=chr( (ord(code[i])-i)%128 )
print(input1)
~~~

### 相册

jadx打开。搜.com，有点弱智。

搜mail，有一个sendMailByJavaMail

~~~java
m.set_host(C2.MAILHOST);
m.set_port(C2.PORT);
m.set_debuggable(true);
m.set_to(new String[]{mailto});
m.set_from(C2.MAILFROME);
m.set_subject(title);
m.setBody(mailmsg);
~~~

去c2看看

~~~java
    public static final String CANCELNUMBER = "%23%2321%23";
    public static final String MAILFROME = Base64.decode(NativeMethod.m());
    public static final String MAILHOST = "smtp.163.com";
    public static final String MAILPASS = Base64.decode(NativeMethod.pwd());
    public static final String MAILSERVER = Base64.decode(NativeMethod.m());
    public static final String MAILUSER = Base64.decode(NativeMethod.m());
    public static final String MOVENUMBER = "**21*121%23";
    public static final String PORT = "25";
    public static final String date = "2115-11-1";
    public static final String phoneNumber = Base64.decode(NativeMethod.p());

~~~

~~~java
package com.net.cn;
public class NativeMethod {
public static native String m();
public static native String p();
public static native String pwd();
}
~~~

不知道这是什么。

>   一个Native Method就是一个Java调用非java代码的接口
>
>   "A native method is a Java method whose implementation is provided by non-java code."

wp：Java中NativeMethod一般用于调用外部文件，再用IDA打libcore.so

### easyRE

在sub_4009C6()里有

char v57[36]

if ( (unsigned __int8)(v57[i] ^ i) != *(&v21 + i) 

写个代码看看

~~~python
b=a.replace(' ','')
c=b.replace('\n','')
#c='v21=73;v22=111;v23=100;v24=108;v25=62;v26=81;v27=110;v28=98;v29=40;v30=111;v31=99;v32=121;v33=127;v34=121;v35=46;v36=105;v37=127;v38=100;v39=96;v40=51;v41=119;v42=125;v43=119;v44=101;v45=107;v46=57;v47=123;v48=105;v49=121;v50=61;v51=126;v52=121;v53=76;v54=64;v55=69;v56=67'
fin=re.sub(r'v..=', "", c)
num=fin.split(';')
print(num)
I=len(num)
s=''
for i in range(I):
    s+=chr(int(num[i])^i)
print(s)
~~~



Info:The first four chars are `flag`

sub_400E44是base64

~~~c
    if ( v9 == 39 )
    {
      v10 = sub_400E44((const __m128i *)&v59);
      v11 = sub_400E44((const __m128i *)v10);
      v12 = sub_400E44((const __m128i *)v11);
      v13 = sub_400E44((const __m128i *)v12);
      v14 = sub_400E44((const __m128i *)v13);
      v15 = sub_400E44((const __m128i *)v14);
      v16 = sub_400E44((const __m128i *)v15);
      v17 = sub_400E44((const __m128i *)v16);
      v18 = sub_400E44((const __m128i *)v17);
      v19 = sub_400E44((const __m128i *)v18);
      v2 = off_6CC090;
      v3 = (char *)v19;
      if ( !sub_400360(v19, off_6CC090) )
~~~

10次，最后和off_6CC090比：

>   Vm0wd2VHUXhTWGhpUm1SWVYwZDRWVll3Wkc5WFJsbDNXa1pPVlUxV2NIcFhhMk0xVmpKS1NHVkdXbFpOYmtKVVZtcEtTMUl5VGtsaVJtUk9ZV3hhZVZadGVHdFRNVTVYVW01T2FGSnRVbGhhVjNoaFZWWmtWMXBFVWxSTmJFcElWbTAxVDJGV1NuTlhia0pXWWxob1dGUnJXbXRXTVZaeVdrWm9hVlpyV1hwV1IzaGhXVmRHVjFOdVVsWmlhMHBZV1ZSR1lWZEdVbFZTYlhSWFRWWndNRlZ0TVc5VWJGcFZWbXR3VjJKSFVYZFdha1pXWlZaT2NtRkhhRk5pVjJoWVYxZDBhMVV3TlhOalJscFlZbGhTY1ZsclduZGxiR1J5VmxSR1ZXSlZjRWhaTUZKaFZqSktWVkZZYUZkV1JWcFlWV3BHYTFkWFRrZFRiV3hvVFVoQ1dsWXhaRFJpTWtsM1RVaG9hbEpYYUhOVmJUVkRZekZhY1ZKcmRGTk5Wa3A2VjJ0U1ExWlhTbFpqUldoYVRVWndkbFpxUmtwbGJVWklZVVprYUdFeGNHOVhXSEJIWkRGS2RGSnJhR2hTYXpWdlZGVm9RMlJzV25STldHUlZUVlpXTlZadE5VOVdiVXBJVld4c1dtSllUWGhXTUZwell6RmFkRkpzVWxOaVNFSktWa1phVTFFeFduUlRhMlJxVWxad1YxWnRlRXRXTVZaSFVsUnNVVlZVTURrPQ==

https://bbs.pediy.com/thread-254172.htm

毛线啊神经病

不知道该怎么下手，看wp

~~~
.data:00000000006CC0A0 byte_6CC0A0     db 40h                  ; DATA XREF: sub_400D35+95r
.data:00000000006CC0A0                                         ; sub_400D35+C1r
.data:00000000006CC0A1                 db  35h ; 5
.data:00000000006CC0A2                 db  20h
.data:00000000006CC0A3 byte_6CC0A3     db 56h                  ; DATA XREF: sub_400D35+A6r
.data:00000000006CC0A4                 db  5Dh ; ]
.data:00000000006CC0A5                 db  18h
.data:00000000006CC0A6                 db  22h ; "
.data:00000000006CC0A7                 db  45h ; E
.data:00000000006CC0A8                 db  17h
.data:00000000006CC0A9                 db  2Fh ; /
.data:00000000006CC0AA                 db  24h ; $
.data:00000000006CC0AB                 db  6Eh ; n
.data:00000000006CC0AC                 db  62h ; b
.data:00000000006CC0AD                 db  3Ch ; <
.data:00000000006CC0AE                 db  27h ; '
.data:00000000006CC0AF                 db  54h ; T
.data:00000000006CC0B0                 db  48h ; H
.data:00000000006CC0B1                 db  6Ch ; l
.data:00000000006CC0B2                 db  24h ; $
.data:00000000006CC0B3                 db  6Eh ; n
.data:00000000006CC0B4                 db  72h ; r
.data:00000000006CC0B5                 db  3Ch ; <
.data:00000000006CC0B6                 db  32h ; 2
.data:00000000006CC0B7                 db  45h ; E
.data:00000000006CC0B8                 db  5Bh ; [
~~~



~~~c
v7 = v4;
v9 = BYTE3(v4);
if ( ((unsigned __int8)v4 ^ byte_6CC0A0[0]) == 102 && (v9 ^ (unsigned __int8)byte_6CC0A3) == 103 )
  {
    for ( j = 0; j <= 24; ++j )
    {
      v2 = (unsigned __int8)(byte_6CC0A0[(signed __int64)j] ^ *((_BYTE *)&v7
                                                              + (signed int)(((((unsigned int)((unsigned __int64)j >> 32) >> 30)
                                                                             + (_BYTE)j) & 3)
                                                                           - ((unsigned int)((unsigned __int64)j >> 32) >> 30))));
      sub_410E90(v2);
    }
  }
~~~

102是f，103是g。byte_6CC0A0应该是flag，先把v7解出来

~~~python
key = ''
enc1 = 'flag'
dec = ''
enc = [0x40,0x35,0x20,0x56,0x5D,0x18,0x22,0x45,0x17,0x2F,0x24,0x6E,0x62,0x3C,0x27,0x54,0x48,0x6C,0x24,0x6E,0x72,0x3C,0x32,0x45,0x5B]
for i in range(4):
    key += chr(enc[i] ^ ord(enc1[i]))
print (key)

for i in range(len(enc)):
    dec += chr(enc[i] ^ ord(key[i%4]))
print(dec)
~~~

https://www.cnblogs.com/Mayfly-nymph/p/11869959.html

脱壳

shift+f12字符串表

alt+t搜索字符串

f5伪代码

c强制转换代码

写py



## day8   5.12

### singin

~~~c
  v8 = *MK_FP(__FS__, 40LL);
  puts("[sign in]");
  printf("[input your flag]: ");
  __isoc99_scanf("%99s", &v6);
  sub_96A(&v6, &v7);
  __gmpz_init_set_str(&v5, "ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35", 16LL);
  __gmpz_init_set_str(&v4, &v7, 16LL);
  __gmpz_init_set_str(&v2, "103461035900816914121390101299049044413950405173712170434161686539878160984549", 10LL);
  __gmpz_init_set_str(&v3, "65537", 10LL);
  __gmpz_powm(&v4, &v4, &v3, &v2);
  if ( __gmpz_cmp(&v4, &v5) )
    puts("GG!");
  else
    puts("TTTTTTTTTTql!");
~~~

v6=flag

 sub_96A：v6变v7

~~~c
size_t __fastcall sub_96A(const char *a1, __int64 a2)
{
  size_t result; // rax@3
  int v3; // [sp+18h] [bp-18h]@1
  int i; // [sp+1Ch] [bp-14h]@1

  v3 = 0;
  for ( i = 0; ; i += 2 )
  {
    result = strlen(a1);
    if ( v3 >= result )
      break;
    *(_BYTE *)(a2 + i) = byte_202010[(char)(a1[v3] >> 4)];
    *(_BYTE *)(a2 + i + 1LL) = byte_202010[a1[v3++] & 0xF];
  }
  return result;
}
~~~
byte_202010：16进制0-f
~~~
db 30h, 31h, 32h, 33h, 34h, 35h, 36h, 37h, 38h, 39h, 61h 62h, 63h, 64h, 65h, 66h
~~~

__gmpz_init_set_str：

>   　GMP(The GNU Multiple Precision Arithmetic Library)又叫GNU多精度算术库，是一个提供了很多操作高精度的大整数，浮点数的运算的算术库，几乎没有什么精度方面的限制，功能丰富。

__gmpz_powm

>   gmp_powm()是PHP中的一个内置函数，用于计算以另一个GMP数模数模拟的两个GMP数的幂。（GNU Multiple Precision：For large number）

没有查到__gmpz_init_set_str具体干嘛的，应该是字符串转数字，gmpz_powm指数模。但是看到65537，rsa。

~~~python
import binascii
def egcd(a,b):         #扩展欧几里得算法
    if a==0:
        return  (b,0,1)
    else:
        g,y,x=egcd(b%a,a)
        return (g,x-(b//a)*y,y)
 
def modinv(a,m):
    g,x,y=egcd(a,m)
    if g!=1:
        raise Exception('modular inverse does not exist')
    else:
        return x%m
c_hex='ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35'
c=int(c_hex,16)
print(c)

n=103461035900816914121390101299049044413950405173712170434161686539878160984549
p=282164587459512124844245113950593348271
q=366669102002966856876605669837014229419
e=65537
fn=(p-1)*(q-1)
d=modinv(e,fn)
m=pow(c,d,n)
print(m)
#m_hex=hex(m)
#print(m_hex)
m_hex='73756374667b50776e5f405f68756e647265645f79656172737d'
print(binascii.a2b_hex(m_hex))

~~~

原来有gmpy2.mpz

https://www.cnblogs.com/ESHLkangi/p/8576222.html

### justre

you dian ji dong.

f5不出来，右键create f

sprintf(&String, aBjdDD2069a4579, 19999, 0);

BJD{1999902069a45792d233ac}

这个分值是为什么啊

[ida F5失败原因1](https://bbs.pediy.com/thread-158896.htm)

[ida F5失败原因2](https://bbs.pediy.com/thread-158896.htm)

## day9 5.13

### strngecpp

没有什么能阻止我获得flag，Orz。

~~~c
  puts("Let me have a look at your computer...");
  for ( j = v16; *(_QWORD *)j; j += 8i64 )
  {
    v14 = *(_QWORD *)j;
    sub_140011226("%s\n", v14);
  }
  std::basic_ostream<char,std::char_traits<char>>::operator<<(std::cout, sub_140011127);
  dword_140021190 = SystemInfo.dwNumberOfProcessors;
  sub_140011226("now system cpu num is %d\n", SystemInfo.dwNumberOfProcessors);
  if ( dword_140021190 < 8 )
  {
    puts("Are you in VM?");
    _exit(0);
  }
  if ( GetUserNameA(Str1, &pcbBuffer) )
  {
    LODWORD(v5) = sub_140011172(std::cout, "this is useful");
    std::basic_ostream<char,std::char_traits<char>>::operator<<(v5, sub_140011127);
  }
  LODWORD(v6) = std::basic_ostream<char,std::char_traits<char>>::operator<<(std::cout, sub_140011127);
  LODWORD(v7) = sub_140011172(v6, "ok,I am checking...");
  std::basic_ostream<char,std::char_traits<char>>::operator<<(v7, sub_140011127);
  if ( !j_strcmp(Str1, "cxx") )
  {
    LODWORD(v8) = sub_140011172(std::cout, "flag{where_is_my_true_flag?}");
    std::basic_ostream<char,std::char_traits<char>>::operator<<(v8, sub_140011127);
    _exit(0);
  }
  system("pause");
  sub_1400113E3(&v10, &unk_14001DE50);
  return sub_140011104((unsigned __int64)&v11 ^ v15);
}

~~~

我觉得flag应该在：

~~~
sub_1400113E3((__int64)&v10, (__int64)&unk_14001DE50);
~~~

~~~c
int __fastcall sub_140014860(__int64 a1, __int64 a2)
{
  int v2; // ebx@1
  __int64 v3; // rsi@1
  __int64 v4; // rbp@1
  __int64 v5; // rdi@2
  __int64 v6; // rdx@3
  __int64 v7; // rcx@3
  __int64 v8; // rax@4
  void *retaddr; // [sp+28h] [bp+0h]@5

  v2 = 0;
  v3 = a2;
  v4 = a1;
  if ( *(_DWORD *)a2 > 0 )
  {
    v5 = 0i64;
    do
    {
      v6 = *(_QWORD *)(v3 + 8);
      v7 = *(_DWORD *)(v6 + v5);
      if ( *(_DWORD *)(v7 + v4 - 4) != -858993460
        || (v8 = v7 + *(_DWORD *)(v6 + v5 + 4), *(_DWORD *)(v8 + v4) != -858993460) )
        LODWORD(v8) = sub_14001117C(retaddr, *(_QWORD *)(v6 + v5 + 8));
      ++v2;
      v5 += 16i64;
    }
    while ( v2 < *(_DWORD *)v3 );
  }
  return v8;
}
~~~

unk_14001DE50=10000000

0i64、16i64应该是64位整数。

-858993460是啥0xcccccccc

等等

~~~
v15 = (unsigned __int64)&v11 ^ _security_cookie;
return sub_140011104((unsigned __int64)&v11 ^ v15);
~~~

_security_cookie=47936899621426：i64。好像没什么用。

找到一些奇怪的东西

~~~
db 26h, 2Ch, 21h, 27h, 3Bh, 0Dh, 4, 75h, 68h, 34h, 28h
db 25h, 0Eh, 35h, 2Dh, 69h, 3Dh
~~~

~~~c
int sub_140013580()
{
  __int64 *v0; // rdi@1
  signed __int64 i; // rcx@1
  int result; // eax@4
  __int64 v3; // [sp+0h] [bp-20h]@1
  int v4; // [sp+24h] [bp+4h]@4
  int j; // [sp+44h] [bp+24h]@6
  __int64 v6; // [sp+128h] [bp+108h]@4

  v0 = &v3;
  for ( i = 82i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 = (__int64 *)((char *)v0 + 4);
  }
  v6 = -2i64;
  sub_1400110AA(&unk_140027033);
  result = sub_140011384((unsigned int)dword_140021190);
  v4 = result;
  if ( result == 607052314 && dword_140021190 <= 14549743 )
  {
    for ( j = 0; j < 17; ++j )
    {
      putchar((unsigned __int8)(dword_140021190 ^ byte_140021008[j]));
      result = j + 1;
    }
  }
  return result;
}
~~~

~~~c
signed __int64 __fastcall sub_140013890(signed int a1)
{
  __int64 *v1; // rdi@1
  signed __int64 i; // rcx@1
  signed __int64 result; // rax@5
  __int64 v4; // [sp+0h] [bp-20h]@1
  int v5; // [sp+24h] [bp+4h]@4
  int v6; // [sp+44h] [bp+24h]@4
  int v7; // [sp+64h] [bp+44h]@4
  signed int v8; // [sp+160h] [bp+140h]@1

  v8 = a1;
  v1 = &v4;
  for ( i = 82i64; i; --i )
  {
    *(_DWORD *)v1 = -858993460;
    v1 = (__int64 *)((char *)v1 + 4);
  }
  sub_1400110AA(&unk_140027033);
  v5 = v8 >> 12;
  v6 = v8 << 8;
  v7 = (v8 << 8) ^ (v8 >> 12);
  v7 *= 291;
  if ( v7 )
    result = (unsigned int)v7;
  else
    result = 987i64;
  return result;
}
~~~

dword_140021190通过sub_140013890变成了result

~~~python

'''
result = 607052314
for i in range(14549743):
    print(i)
    v8=i
    v7 = (v8 << 8) ^ (v8 >> 12)
    v7 *= 291
    if v70xFFFFFFFF==result:
        print(i)
        break
'''
result = 123456
a='26h, 2Ch, 21h, 27h, 3Bh, 0Dh, 4, 75h, 68h, 34h, 28h,25h, 0Eh, 35h, 2Dh, 69h, 3Dh'
b=a.replace('h','')
c=b.replace(' ','')
d=c.split(',')
for i in range(len(d)):
    d[i]='0x'+d[i]
print(d)
flag = ""
for i in d:
    flag += chr((result ^ int(i,16))&0xFF) 
print(flag)
import hashlib

md5 = hashlib.md5()
md5.update('123456')
print md5.hexdigest()

~~~

[没有注意unsigned int和int的我像个弱智跑了好久](https://www.cnblogs.com/Mayfly-nymph/p/12609782.html)

## day10   5.14 

又是元气满满的一天。

我最乐于助人了。

。。。

路由器固件dump文件，tplink我倒是看到了

binwalk -e 后有个.squashfs、7z压缩包、证书、空文件夹

>   Squashfs是一个只读格式的文件系统，具有超高压缩率，其压缩率最高可达34%。当系统启动后，会将文件系统保存在一个压缩过的文件系统的文件中，这个文件可以使用换回的形式挂载并对其中的文件进行访问，当进程需要某些文件时，仅将对应部分的压缩文件解压缩。
>
>   　　Squashfs文件系统常用的压缩格式有GZIP、LZMA、LZO、XZ(LZMA2)，在路由器中被普遍采用。路由器的根文件系统通常会按照Squashfs文件系统常用压缩格式中的一种进行打包，形成一个完整的Squashfs文件系统，然后与路由器操作系统的内核一起形成更新固件。

然后呢。网上查

用unsquashfs命令解压

![](firmware/Snipaste_2020-05-14_20-38-27.png)

去ubuntu试试，不行。

查报错，。。。算了看wp

>   firmware-mod-kit工具的功能和binwalk工具的类似，实际上firmware-mod- kitfirm工具在功能上有调用binwalk工具提供的功能以及其他的固件解包工具的整合。下载firmware-mod-kit工具的链接进入到src目录下就能够看到firmware-mod-kit工具整合了那些固件提取和文件系统解压的工具。firmware-mod-kit工具的功能有固件文件的解包和打包，固件提取文件系统的解压和压缩，DD-WRT
>   网页的修改等，在每个整合的固件分析中工具的源码文件夹里都有相关的使用说明。

~~~
sudo apt-get install git build-essential zlib1g-dev liblzma-dev python-magic
git clone https://github.com/mirror/firmware-mod-kit.git
cd firmware-mod-kit/src
./configure && make
~~~

[gitclone慢](https://www.linuxidc.com/Linux/2019-05/158461.htm)没什么用，fq也是

~~~
./unsquashfs_all.sh 120200.squashfs
~~~



[emmm手动](https://www.cnblogs.com/blacksunny/p/7208451.html?utm_source=itdadao&utm_medium=referral)

## day11 5.15

*路漫漫其修远兮，吾将上下而求索！*

***

### re

好短，有壳吧。

脱壳。

搜了一波。

找到aInputYourFlag，

~~~c
sub_40F950((__int64)"input your flag:", 0LL, 0LL, 0LL, 0LL);
sub_40FA80((__int64)"%s", &v4);
if ( (unsigned int)sub_4009AE(&v4, &v4) )
{
v0 = "Correct!";
sub_410350("Correct!");
~~~



~~~
sub_40F950(-92);
  sub_40FA80(-75);
  if ( sub_4009AE(&v2, &v2) )
  {
    v0 = 4855992LL;
    sub_410350(4855992LL);
    result = 0LL;
  }
~~~

sub_4009ae里

~~~
__int64 __fastcall sub_4009AE(__int64 a1)
{
  __int64 result; // rax@2

  if ( 1629056 * *(_BYTE *)a1 == 166163712 )
  {
    if ( 6771600 * *(_BYTE *)(a1 + 1) == 731332800 )
    {
      if ( 3682944 * *(_BYTE *)(a1 + 2) == 357245568 )
      {
        if ( 10431000 * *(_BYTE *)(a1 + 3) == 1074393000 )
        {
          if ( 3977328 * *(_BYTE *)(a1 + 4) == 489211344 )
          {
            if ( 5138336 * *(_BYTE *)(a1 + 5) == 518971936 )
            {
              if ( 7532250 * *(_BYTE *)(a1 + 7) == 406741500 )
              {
                if ( 5551632 * *(_BYTE *)(a1 + 8) == 294236496 )
                {
                  if ( 3409728 * *(_BYTE *)(a1 + 9) == 177305856 )
                  {
                    if ( 13013670 * *(_BYTE *)(a1 + 10) == 650683500 )
                    {
                      if ( 6088797 * *(_BYTE *)(a1 + 11) == 298351053 )
                      {
                        if ( 7884663 * *(_BYTE *)(a1 + 12) == 386348487 )
                        {
                          if ( 8944053 * *(_BYTE *)(a1 + 13) == 438258597 )
                          {
                            if ( 5198490 * *(_BYTE *)(a1 + 14) == 249527520 )
                            {
                              if ( 4544518 * *(_BYTE *)(a1 + 15) == 445362764 )
                              {
                                if ( 3645600 * *(_BYTE *)(a1 + 17) == 174988800 )
                                {
                                  if ( 10115280 * *(_BYTE *)(a1 + 16) == 981182160 )
                                  {
                                    if ( 9667504 * *(_BYTE *)(a1 + 18) == 493042704 )
                                    {
                                      if ( 5364450 * *(_BYTE *)(a1 + 19) == 257493600 )
                                      {
                                        if ( 13464540 * *(_BYTE *)(a1 + 20) == 767478780 )
                                        {
                                          if ( 5488432 * *(_BYTE *)(a1 + 21) == 312840624 )
                                          {
                                            if ( 14479500 * *(_BYTE *)(a1 + 22) == 1404511500 )
                                            {
                                              if ( 6451830 * *(_BYTE *)(a1 + 23) == 316139670 )
                                              {
                                                if ( 6252576 * *(_BYTE *)(a1 + 24) == 619005024 )
                                                {
                                                  if ( 7763364 * *(_BYTE *)(a1 + 25) == 372641472 )
                                                  {
                                                    if ( 7327320 * *(_BYTE *)(a1 + 26) == 373693320 )
                                                    {
                                                      if ( 8741520 * *(_BYTE *)(a1 + 27) == 498266640 )
                                                      {
                                                        if ( 8871876 * *(_BYTE *)(a1 + 28) == 452465676 )
                                                        {
                                                          if ( 4086720 * *(_BYTE *)(a1 + 29) == 208422720 )
                                                          {
                                                            if ( 9374400 * *(_BYTE *)(a1 + 30) == 515592000 )
                                                              result = 5759124 * *(_BYTE *)(a1 + 31) == 719890500;
                                                            else
                                                              result = 0LL;
                                                          }
                                                          else
                                                          {
                                                            result = 0LL;
                                                          }
                                                        }
                                                        else
                                                        {
                                                          result = 0LL;
                                                        }
                                                      }
                                                      else
                                                      {
                                                        result = 0LL;
                                                      }
                                                    }
                                                    else
                                                    {
                                                      result = 0LL;
                                                    }
                                                  }
                                                  else
                                                  {
                                                    result = 0LL;
                                                  }
                                                }
                                                else
                                                {
                                                  result = 0LL;
                                                }
                                              }
                                              else
                                              {
                                                result = 0LL;
                                              }
                                            }
                                            else
                                            {
                                              result = 0LL;
                                            }
                                          }
                                          else
                                          {
                                            result = 0LL;
                                          }
                                        }
                                        else
                                        {
                                          result = 0LL;
                                        }
                                      }
                                      else
                                      {
                                        result = 0LL;
                                      }
                                    }
                                    else
                                    {
                                      result = 0LL;
                                    }
                                  }
                                  else
                                  {
                                    result = 0LL;
                                  }
                                }
                                else
                                {
                                  result = 0LL;
                                }
                              }
                              else
                              {
                                result = 0LL;
                              }
                            }
                            else
                            {
                              result = 0LL;
                            }
                          }
                          else
                          {
                            result = 0LL;
                          }
                        }
                        else
                        {
                          result = 0LL;
                        }
                      }
                      else
                      {
                        result = 0LL;
                      }
                    }
                    else
                    {
                      result = 0LL;
                    }
                  }
                  else
                  {
                    result = 0LL;
                  }
                }
                else
                {
                  result = 0LL;
                }
              }
              else
              {
                result = 0LL;
              }
            }
            else
            {
              result = 0LL;
            }
          }
          else
          {
            result = 0LL;
          }
        }
        else
        {
          result = 0LL;
        }
      }
      else
      {
        result = 0LL;
      }
    }
    else
    {
      result = 0LL;
    }
  }
  else
  {
    result = 0LL;
  }
  return result;
}
~~~

32位a1。

### crackMe

32位。

~~~c
  while ( 1 )
  {
    do
    {
      do
      {
        printf("user(6-16 letters or numbers):");
        scanf("%s", &v10);
        v0 = (FILE *)sub_4024BE();
        sub_4022E7(v0);
      }
      while ( !(unsigned __int8)sub_401000(&v10) );
      printf("password(6-16 letters or numbers):");
      scanf("%s", &v8);
      v1 = (FILE *)sub_4024BE();
      sub_4022E7(v1);
    }
    while ( !(unsigned __int8)sub_401000(&v8) );
    sub_401090(&v10);
    v6 = 0;
    memset(&v7, 0, 0xFFu);
    v4 = 0;
    memset(&v5, 0, 0xFFu);
    v3 = ((int (__cdecl *)(char *, char *))loc_4011A0)(&v6, &v4);
    if ( (unsigned __int8)sub_401830(&v10, &v8) )
    {
      if ( v3 )
        break;
    }
    printf(&v4);
  }
  printf(&v6);
  return 0;
~~~



sub_4020E5==printf

sub_402194==scanf

sub_401000应该是判断用户存在。。是判断输入合法

~~~c
char __cdecl sub_401000(const char *a1)
{
  char result; // al@3
  unsigned int v2; // [sp+8h] [bp-10h]@1
  signed int i; // [sp+Ch] [bp-Ch]@4

  v2 = strlen(a1);
  if ( (signed int)v2 >= 6 || (signed int)v2 <= 16 )
  {
    for ( i = 0; i < (signed int)v2; ++i )
    {
      if ( !isalnum(a1[i]) )
        return 0;
    }
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
~~~

关键应该是sub_401830，它同时调用user和password

~~~c
bool __usercall sub_401830@<al>(signed int ebx0@<ebx>, int a1, const char *a2)
{
  signed int v4; // [sp+18h] [bp-22Ch]@1
  unsigned int v5; // [sp+1Ch] [bp-228h]@1
  unsigned int v6; // [sp+28h] [bp-21Ch]@1
  unsigned int v7; // [sp+30h] [bp-214h]@1
  char v8; // [sp+36h] [bp-20Eh]@14
  char v9; // [sp+37h] [bp-20Dh]@4
  char v10; // [sp+38h] [bp-20Ch]@1
  char v11; // [sp+39h] [bp-20Bh]@1
  char v12; // [sp+3Ah] [bp-20Ah]@1
  char v13; // [sp+3Bh] [bp-209h]@14
  int v14; // [sp+3Ch] [bp-208h]@21
  char v15; // [sp+40h] [bp-204h]@1
  char v16; // [sp+41h] [bp-203h]@1
  char v17; // [sp+140h] [bp-104h]@1
  char v18; // [sp+141h] [bp-103h]@1

  v5 = 0;
  v6 = 0;
  v12 = 0;
  v11 = 0;
  v17 = 0;
  memset(&v18, 0, 0xFFu);
  v15 = 0;
  memset(&v16, 0, 0xFFu);
  v10 = 0;
  v7 = 0;
  v4 = 0;
  while ( v7 < strlen(a2) )
  {
    if ( isdigit(a2[v7]) )
    {
      v9 = a2[v7] - 48;
    }
    else if ( isxdigit(a2[v7]) )
    {
      if ( *(_DWORD *)(*(_DWORD *)(__readfsdword(48) + 24) + 12) != 2 )
        a2[v7] = 34;
      v9 = (a2[v7] | 0x20) - 87;
    }
    else
    {
      v9 = ((a2[v7] | 0x20) - 97) % 6 + 10;
    }
    v10 = v9 + 16 * v10;
    /***
    选a2偶数位的数值给v15
    ***/
    if ( !((signed int)(v7 + 1) % 2) )
    {
      *(&v15 + v4++) = v10;
      ebx0 = v4;
      v10 = 0;
    }
    ++v7;
  }
  while ( (signed int)v6 < 8 )
  {
    ++v12;
    v11 += byte_416050[(unsigned __int8)v12];
    v13 = byte_416050[(unsigned __int8)v12];
    v8 = byte_416050[(unsigned __int8)v11];
    byte_416050[(unsigned __int8)v11] = v13;
    byte_416050[(unsigned __int8)v12] = v8;
    if ( *(_DWORD *)(__readfsdword(48) + 104) & 0x70 )
      v13 = v11 + v12;
    /***
    v17有8位，byte_416050[不知道什么鬼]^v15。（v5=v6）
    ***/
    *(&v17 + v6) = byte_416050[(unsigned __int8)(v8 + v13)] ^ *(&v15 + v5);
    if ( *(_DWORD *)(__readfsdword(48) + 2) & 0xFF )
    {
      v11 = -83;
      v12 = 43;
    }
    sub_401710((int)&v17, (const char *)a1, v6++);
    v5 = v6;
    if ( v6 >= strlen(&v15) )
      v5 = 0;
  }
  v14 = 0;
  sub_401470(ebx0, (int)&v17, (int)&v14);
  return v14 == 43924;
}
~~~

sub_401470，传v17，使v14=43924

sub_401470里发现多个 if ( *(_BYTE *)a2 == '字符' )，v17=dbappsec。

byte_416050在sub_401090(user)生成。不不不感谢https://www.cnblogs.com/basstorm/p/12662023.html。



绕过三个if反调试（__readfsdword）

![](crackMe/Snipaste_2020-05-15_19-38-24.png)

![](crackMe/Snipaste_2020-05-15_19-38-39.png)

![](crackMe/Snipaste_2020-05-15_19-38-52.png)

![](crackMe/Snipaste_2020-05-15_19-37-47.png)

~~~python
v = [0x2a,0xd7,0x92,0xe9,0x53,0xe2,0xc4,0xcd]
a ='dbappsec'
ps=''
for i in range(8):
    ps+=hex(ord(a[i])^v[i])[2:]
print(ps)
~~~

可以说这是我目前为止遇到最难的，结合wp搞了一下午。反调试看了https://www.cnblogs.com/Crisczy/p/7575521.html，简单理解了一下。



## day12 5.16

### [GUET-2019]re

掐指一算有壳。

根据sub_4009AE写脚本。

这里可以用Z3约束器，也可以用515592000//9374400直接求a1。

~~~python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from z3 import *

from z3 import*
#申明未知量
a1 = [0]*32
for i in range(32):
    a1[i] = Int('a1['+str(i)+']')
s=Solver() # 创建约束求解器

# 添加约束条件
s.add( 1629056 * a1[0] == 166163712 )
s.add( 6771600 * a1[1] == 731332800 )
s.add( 3682944 * a1[2] == 357245568 )
s.add( 10431000 * a1[3] == 1074393000 )
s.add( 3977328 * a1[4] == 489211344 )
s.add( 5138336 * a1[5] == 518971936 )
s.add( 7532250 * a1[7] == 406741500 )
s.add( 5551632 * a1[8] == 294236496 )
s.add( 3409728 * a1[9] == 177305856 )
s.add( 13013670 * a1[10] == 650683500 )
s.add( 6088797 * a1[11] == 298351053 )
s.add( 7884663 * a1[12] == 386348487 )
s.add( 8944053 * a1[13] == 438258597 )
s.add( 5198490 * a1[14] == 249527520 )
s.add( 4544518 * a1[15] == 445362764 )
s.add( 3645600 * a1[17] == 174988800 )
s.add( 10115280 * a1[16] == 981182160 )
s.add( 9667504 * a1[18] == 493042704 )
s.add( 5364450 * a1[19] == 257493600 )
s.add( 13464540 * a1[20] == 767478780 )
s.add( 5488432 * a1[21] == 312840624 )
s.add( 14479500 * a1[22] == 1404511500 )
s.add( 6451830 * a1[23] == 316139670 )
s.add( 6252576 * a1[24] == 619005024 )
s.add( 7763364 * a1[25] == 372641472 )
s.add( 7327320 * a1[26] == 373693320 )
s.add( 8741520 * a1[27] == 498266640 )
s.add( 8871876 * a1[28] == 452465676 )
s.add( 4086720 * a1[29] == 208422720 )
s.add( 9374400 * a1[30] == 515592000 )
s.add(5759124 * a1[31] == 719890500)
# 检查是否有解
if s.check()!="sat":
    print( "unsat")

m=s.model()
for d in m.decls():   # decls()返回model包含了所有符号的列表
    print("%s = %s" % (d.name(),m[d]))
print(515592000//9374400)
~~~

a1[6]没有。没想到爆破。1

## day13 5.17

### CSre

有壳。Eazfuscator.NET http://github.com/0xd4d/de4dot

什么乱七八糟的东西。

![](csre/Snipaste_2020-05-17_17-05-21.png)

![](csre/Snipaste_2020-05-17_17-20-18.png)

dnspy真好看，class3.method_0是sha1。

~~~java
public static string smethod_0(string string_0)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(string_0);
		byte[] array = SHA1.Create().ComputeHash(bytes);
		StringBuilder stringBuilder = new StringBuilder();
		foreach (byte b in array)
		{
			stringBuilder.Append(b.ToString("X2"));
		}
		return stringBuilder.ToString();
~~~

314159

return

去掉39re

## day14 5.18

### [ACTF新生赛2020]easyre

upx脱壳

>   LOWORD()得到一个32bit数的低16bit  
>   HIWORD()得到一个32bit数的高16bit
>   LOBYTE()得到一个16bit数最低（最右边）那个字节
>   HIBYTE()得到一个16bit数最高（最左边）那个字节

~~~c
  __main();
  v4 = 42;
  v5 = 70;
  v6 = 39;
  v7 = 34;
  v8 = 78;
  v9 = 44;
  v10 = 34;
  v11 = 40;
  v12 = 73;
  v13 = 63;
  v14 = 43;
  v15 = 64;
  printf("Please input:");
  scanf("%s", &v19);
  if ( (_BYTE)v19 == 'A' && HIBYTE(v19) == 'C' && v20 == 'T' && v21 == 'F' && v22 == '{' && v26 == '}' )
  {
    v16 = v23;
    v17 = v24;
    v18 = v25;
    for ( i = 0; i <= 11; ++i )
    {
      if ( *(&v4 + i) != _data_start__[*((_BYTE *)&v16 + i) - 1] )
        return 0;
    }
    printf("You are correct!");
    result = 0;
  }
~~~

~~~
.data:00402000 __data_start__  db 7Eh                  ; DATA XREF: _main+ECr
.data:00402001 aZyxwvutsrqponm db '}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>='
.data:00402001                 db '<;:9876543210/.-,+*)(',27h,'&%$# !"',0
~~~

~~~python
data='~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)(\'&%$# !"'
print(data)
v4 = [42,70,39,34,78,44,34,40,73,63,43,64]
flag=''

for n in v4:
    flag+=chr(data.find(chr(n))+1)
print flag
~~~

起飞

### [FlareOn4]login

~~~html

<!DOCTYPE Html />
<html>
    <head>
        <title>FLARE On 2017</title>
    </head>
    <body>
        <input type="text" name="flag" id="flag" value="Enter the flag" />
        <input type="button" id="prompt" value="Click to check the flag" />
        <script type="text/javascript">
            document.getElementById("prompt").onclick = function () {
                var flag = document.getElementById("flag").value;
                var rotFlag = flag.replace(/[a-zA-Z]/g, function(c){return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);});
                if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
                    alert("Correct flag!");
                } else {
                    alert("Incorrect flag, rot again");
                }
            }
        </script>
    </body>
</html>

~~~

~~~javascript
JavaScript fromCharCode() 方法将 Unicode 编码转为一个字符:
var n = String.fromCharCode(65);
n 
输出结果:A
charCodeAt() 方法可返回指定位置的字符的 Unicode 编码
~~~

~~~python
'''
    (c <= "Z"? 90 : 122) >= (c + 13)
    ? c+13 : c - 13
'''
#M77 m109
ef='PyvragFvqrYbtvafNerRnfl@syner-ba.pbz'
flag=''

for i in ef:
    if i<'A' or i>'z' or 'Z'<i<'a':
        flag+=i
        continue
    if 'Z'>=i>'M' or 'z'>=i>'m':
        flag+=chr(ord(i)-13)
    else:
        flag+=chr(ord(i)+13)
print flag
~~~

一开始条件没写全。

## day15 5.19

### [BJDCTF2020]easy

没壳。

~~~c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+10h] [bp-3F0h]@1
  struct tm *v5; // [sp+3FCh] [bp-4h]@1

  __main();
  time((time_t *)&v4);
  v5 = localtime((const time_t *)&v4);
  puts("Can you find me?\n");
  system("pause");
  return 0;
}
~~~

找，感觉和时间有关。v5是当前时间tm类。

字符串什么的都没有，再找可疑的数据。

~~~c
int ques()
{
  int v0; // edx@2
  int result; // eax@16
  int v2[50]; // [sp+20h] [bp-128h]@2
  int v3; // [sp+E8h] [bp-60h]@1
  int v4; // [sp+ECh] [bp-5Ch]@1
  int v5; // [sp+F0h] [bp-58h]@1
  int v6; // [sp+F4h] [bp-54h]@1
  int v7; // [sp+F8h] [bp-50h]@1
  int v8; // [sp+FCh] [bp-4Ch]@1
  int v9; // [sp+100h] [bp-48h]@1
  int v10; // [sp+104h] [bp-44h]@1
  int v11; // [sp+108h] [bp-40h]@1
  int v12; // [sp+10Ch] [bp-3Ch]@1
  int j; // [sp+114h] [bp-34h]@7
  __int64 v14; // [sp+118h] [bp-30h]@2
  int v15; // [sp+124h] [bp-24h]@2
  int v16; // [sp+128h] [bp-20h]@2
  int i; // [sp+12Ch] [bp-1Ch]@1

  v3 = 2147122737;
  v4 = 140540;
  v5 = -2008399303;
  v6 = 141956;
  v7 = 139457077;
  v8 = 262023;
  v9 = -2008923597;
  v10 = 143749;
  v11 = 2118271985;
  v12 = 143868;
  for ( i = 0; i <= 4; ++i )
  {
    memset(v2, 0, sizeof(v2));
    v16 = 0;
    v15 = 0;
    v0 = *(&v4 + 2 * i);
    LODWORD(v14) = *(&v3 + 2 * i);
    HIDWORD(v14) = v0;
    while ( SHIDWORD(v14) > 0 || SHIDWORD(v14) >= 0 && (_DWORD)v14 )
    {
      v2[v16++] = ((SHIDWORD(v14) >> 31) ^ (((unsigned __int8)(SHIDWORD(v14) >> 31) ^ (unsigned __int8)v14)
                                          - (unsigned __int8)(SHIDWORD(v14) >> 31)) & 1)
                - (SHIDWORD(v14) >> 31);
      v14 /= 2LL;
    }
    for ( j = 50; j >= 0; --j )
    {
      if ( v2[j] )
      {
        if ( v2[j] == 1 )
        {
          putchar(42);
          ++v15;
        }
      }
      else
      {
        putchar(32);
        ++v15;
      }
      if ( !(v15 % 5) )
        putchar(32);
    }
    result = putchar(10);
  }
  return result;
}
~~~

#define SHIDWORD(x)  (\*((int32*)&(x)+1))

_ques里。为什么呢

修改eip地址跳转

![](%5BBJDCTF2020%5Deasy/Snipaste_2020-05-19_17-15-39.png)

![](%5BBJDCTF2020%5Deasy/Snipaste_2020-05-19_17-15-55.png)

![](%5BBJDCTF2020%5Deasy/Snipaste_2020-05-19_17-13-58.png)

HACKIT4FUN

>   wp上：函数窗口可以发现一个叫ques的未被调用的函数。

完全看找不找得到。

### [GXYCTF2019]simple CPP

无壳64.

字符串里有，要绕过反调试

![](%5BGXYCTF2019%5Dsimple%20CPP/Snipaste_2020-05-19_17-21-58.png)



函数有个std::_Lockit::~_Lockit(void)没看出什么



~~~c
int sub_140001290()
{
  bool v0; // si@1
  __int64 v1; // rax@1
  void *v2; // rax@2
  void *v3; // rbx@2
  int v4; // er10@5
  __int64 v5; // r11@6
  void *v6; // r9@7
  void **v7; // r8@9
  __int64 v8; // rdi@12
  __int64 v9; // r15@12
  __int64 v10; // r12@12
  __int64 v11; // rbp@12
  signed int v12; // ecx@13
  void *v13; // rdx@14
  __int64 v14; // rdi@15
  void *v15; // r14@27
  __int64 v16; // rbp@29
  __int64 v17; // r13@29
  void *v18; // rdi@29
  __int64 v19; // r12@32
  __int64 v20; // r15@32
  __int64 v21; // rbp@32
  __int64 v22; // rdx@32
  __int64 v23; // rbp@32
  __int64 v24; // rbp@34
  __int64 v25; // r10@34
  __int64 v26; // rdi@34
  __int64 v27; // r8@34
  bool v28; // dl@34
  __int64 v29; // rax@40
  void *v30; // rdx@40
  __int64 v31; // rax@42
  __int64 v32; // rax@44
  void *v33; // rcx@46
  __int64 v35; // [sp+0h] [bp-88h]@50
  __int64 v36; // [sp+20h] [bp-68h]@29
  void *v37; // [sp+28h] [bp-60h]@29
  void *Memory; // [sp+30h] [bp-58h]@1
  unsigned __int64 v39; // [sp+40h] [bp-48h]@1
  unsigned __int64 v40; // [sp+48h] [bp-40h]@1
  __int64 v41; // [sp+50h] [bp-38h]@50

  v0 = 0;
  v39 = 0i64;
  v40 = 15i64;
  LOBYTE(Memory) = 0;
  v1 = sub_1400019C0((__int64)std::cout, (__int64)"I'm a first timer of Logic algebra , how about you?");
  std::basic_ostream<char,std::char_traits<char>>::operator<<(v1, sub_140001B90);
  sub_1400019C0((__int64)std::cout, (__int64)"Let's start our game,Please input your flag:");
  sub_140001DE0((__int64)std::cin, (__int64)&Memory);
  std::basic_ostream<char,std::char_traits<char>>::operator<<(std::cout, sub_140001B90);
  if ( v39 - 5 > 0x19 )
  {
    v32 = sub_1400019C0((__int64)std::cout, (__int64)"Wrong input ,no GXY{} in input words");
    std::basic_ostream<char,std::char_traits<char>>::operator<<(v32, sub_140001B90);
    goto LABEL_45;
  }
  v2 = sub_1400024C8(0x20ui64);
  v3 = v2;
  if ( v2 )
  {
    *(_QWORD *)v2 = 0i64;
    *((_QWORD *)v2 + 1) = 0i64;
    *((_QWORD *)v2 + 2) = 0i64;
    *((_QWORD *)v2 + 3) = 0i64;
  }
  else
  {
    v3 = 0i64;
  }
  v4 = 0;
  if ( v39 > 0 )
  {
    v5 = 0i64;
    do
    {
      v6 = &Memory;
      if ( v40 >= 0x10 )
        v6 = Memory;
      v7 = &Dst;
      if ( (unsigned __int64)qword_140006060 >= 0x10 )
        v7 = (void **)Dst;
      *((_BYTE *)v3 + v5) = *((_BYTE *)v6 + v5) ^ *((_BYTE *)v7 + v4++ % 27);
      ++v5;
    }
    while ( v4 < v39 );
  }
  v8 = 0i64;
  v9 = 0i64;
  v10 = 0i64;
  v11 = 0i64;
  if ( (signed int)v39 > 30 )
    goto LABEL_28;
  v12 = 0;
  if ( (signed int)v39 <= 0 )
    goto LABEL_28;
  v13 = v3;
  do
  {
    v14 = *(_BYTE *)v13 + v8;
    ++v12;
    v13 = (char *)v13 + 1;
    if ( v12 == 8 )
    {
      v11 = v14;
      goto LABEL_24;
    }
    if ( v12 == 16 )
    {
      v10 = v14;
      goto LABEL_24;
    }
    if ( v12 == 24 )
    {
      v9 = v14;
LABEL_24:
      v14 = 0i64;
      goto LABEL_25;
    }
    if ( v12 == 32 )
    {
      sub_1400019C0((__int64)std::cout, (__int64)"ERRO,out of range");
      exit(1);
    }
LABEL_25:
    v8 = v14 << 8;
  }
  while ( v12 < (signed int)v39 );
  if ( v11 )
  {
    v15 = sub_1400024C8(0x20ui64);
    *(_QWORD *)v15 = v11;
    *((_QWORD *)v15 + 1) = v10;
    *((_QWORD *)v15 + 2) = v9;
    *((_QWORD *)v15 + 3) = v8;
    goto LABEL_29;
  }
LABEL_28:
  v15 = 0i64;
LABEL_29:
  v36 = *((_QWORD *)v15 + 2);
  v16 = *((_QWORD *)v15 + 1);
  v17 = *(_QWORD *)v15;
  v18 = sub_14000223C(0x20ui64);
  v37 = v18;
  if ( IsDebuggerPresent() )
  {
    sub_1400019C0((__int64)std::cout, (__int64)"Hi , DO not debug me !");
    Sleep(0x7D0u);
    exit(0);
  }
  v19 = v16 & v17;
  *(_QWORD *)v18 = v16 & v17;
  v20 = v36 & ~v17;
  *((_QWORD *)v18 + 1) = v20;
  v21 = ~v16;
  v22 = v36 & v21;
  *((_QWORD *)v18 + 2) = v36 & v21;
  v23 = v17 & v21;
  *((_QWORD *)v18 + 3) = v23;
  if ( v20 != 1176889593874i64 )
  {
    *((_QWORD *)v18 + 1) = 0i64;
    v20 = 0i64;
  }
  v24 = v20 | v19 | v22 | v23;
  v25 = *((_QWORD *)v15 + 1);
  v26 = *((_QWORD *)v15 + 2);
  v27 = v22 & *(_QWORD *)v15 | v26 & (v19 | v25 & ~*(_QWORD *)v15 | ~(v25 | *(_QWORD *)v15));
  v28 = 0;
  if ( v27 == 577031497978884115i64 )
    v28 = v24 == 4483974544037412639i64;
  if ( (v24 ^ *((_QWORD *)v15 + 3)) == 4483974543195470111i64 )
    v0 = v28;
  if ( (v20 | v19 | v25 & v26) != (~*(_QWORD *)v15 & v26 | 0xC00020130082C0Ci64) || v0 != 1 )
  {
    sub_1400019C0((__int64)std::cout, (__int64)"Wrong answer!try again");
    j_j_free(v3);
  }
  else
  {
    v29 = sub_1400019C0((__int64)std::cout, (__int64)"Congratulations!flag is GXY{");
    v30 = &Memory;
    if ( v40 >= 0x10 )
      v30 = Memory;
    LODWORD(v31) = sub_140001FD0(v29, v30, v39);
    sub_1400019C0(v31, (__int64)"}");
    j_j_free(v3);
  }
LABEL_45:
  if ( v40 >= 0x10 )
  {
    v33 = Memory;
    if ( v40 + 1 >= 0x1000 )
    {
      v33 = (void *)*((_QWORD *)Memory - 1);
      if ( (unsigned __int64)((_BYTE *)Memory - (_BYTE *)v33 - 8) > 0x1F )
      {
        invalid_parameter_noinfo_noreturn();
        __debugbreak();
      }
    }
    j_j_free(v33);
  }
  return sub_140002210((unsigned __int64)&v35 ^ v41);
}
~~~

v3=flag^Dst

v3分割后满足一系列条件

flag条件：

(v20 | v19 | v25 & v26) == (~*(_QWORD *)v15 & v26 | 0xC00020130082C0Ci64)

v0==1

~~~c
v36=v26=v15[2]
v17=v15[0]
v16=v25=v15[1]
v19 = v16 & v17=v15[0]&v15[1]
v21 = ~v16=~v15[1]
v22 = v36 & v21=v15[2]&(~v15[1])
v23 = v17 & v21=v15[0]&(~v15[1])

v20 = v15[2] & ~v15[0]
== 1176889593874
    
v24 = v20 | (v15[1] & v15[0]) | (v15[2] & (~v15[1])) | (v15[0]&(~v15[1]));
==4483974544037412639
    
    
v27 =v15[2]&(~v15[1])& v15[0] |v15[2]& ( (v15[0]&v15[1]) | v15[1] & ~v15[0] | ~(v15[1] | v15[0]) );
==577031497978884115
    
4483974544037412639 ^ v15[3] == 4483974543195470111

(v20 | (v15[0]&v15[1]) | v15[1] & v15[2]) == v15[0] & v15[2] | 0xC00020130082C0C
~~~

给爷爬！！！！

~~~python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from z3 import *

from z3 import*
#申明未知量
v15 = [0]*4
for i in range(4):
    v15[i] = BitVec('v15['+str(i)+']',64)
s=Solver() # 创建约束求解器

# 添加约束条件
s.add(((v15[2]&~v15[1])&v15[0]|v15[2]&((v15[1]&v15[0])|v15[1]&~v15[0]|~(v15[1]|v15[0])))==577031497978884115)
s.add(4483974544037412639 ^ v15[3] == 4483974543195470111)
s.add(v15[2] & ~v15[0]== 1176889593874)
s.add(1176889593874 | (v15[1] & v15[0]) | (v15[2] & (~v15[1])) | (v15[0]&(~v15[1]))==4483974544037412639)
s.add((1176889593874 | (v15[0]&v15[1]) | v15[1] & v15[2]) == ~v15[0] & v15[2] | 864693332579200012)
# 检查是否有解
if s.check()!=sat:
    print( "unsat")

m=s.model()
for d in m.decls():   # decls()返回model包含了所有符号的列表
    print("%s = %s" % (d.name(),m[d]))

~~~



~~~
v15[3] = 842073600
v15[2] = 577031497978884115
v15[0] = 4483973367147818765
v15[1] = 864693332579200012
~~~

~~~c
do
    {
      v6 = &Memory;
      if ( v40 >= 0x10 )
        v6 = Memory;
      v7 = &Dst;
      if ( (unsigned __int64)qword_140006060 >= 0x10 )
        v7 = (void **)Dst;
      *((_BYTE *)v3 + v5) = *((_BYTE *)v6 + v5) ^ *((_BYTE *)v7 + v4++ % 27);
      ++v5;
    }
    while ( v4 < v39 );
~~~

~~~python
v15=[0]*4
v15[0] = 4483973367147818765
v15[2] = 577031497978884115
v15[1] = 864693332579200012
v15[3] = 842073600
for i in range(4):
    v15[i]=hex(v15[i])
    v15[i]=v15[i].replace('L','')
    v15[i]=v15[i].replace('0x','')
print v15
s=''
for i in v15:
    s+=str(i)
print s
flag=''
dst="i_will_check_is_debug_or_not"
n=0
for j in range(0,len(s),2):
    flag+=chr(int(s[j]+s[j+1],16)^ord(dst[n%27]))
    n+=1
print flag
~~~

We1l_D0n╡Cx_氤梖bu`Yo|@nho。emmm有点问题。

看过wp后发现v15[1]错了。我淦，把v15全换成xyzw，一个一个比。

我淦，每个wp v15[1]好像都不一样。

s="3e3a460533286f00000000000000000008020717153e3013323106"

We1l_D0check_is_lgebra_am_i

比赛给了二部分e!P0or_a

我逆了一下，应该是0d44335b301b2c3e80，这样会10进制244722044838787956352转的话没有第一个0。

## day16 5.20

### xxor

应该在sub_400856里

~~~c
__int64 sub_400856()
{
  signed int i; // [sp+8h] [bp-68h]@1
  signed int j; // [sp+Ch] [bp-64h]@4
  __int64 v3; // [sp+10h] [bp-60h]@1
  __int64 v4; // [sp+18h] [bp-58h]@1
  __int64 v5; // [sp+20h] [bp-50h]@1
  __int64 v6; // [sp+28h] [bp-48h]@1
  __int64 v7; // [sp+30h] [bp-40h]@1
  __int64 v8; // [sp+40h] [bp-30h]@4
  __int64 v9; // [sp+48h] [bp-28h]@4
  __int64 v10; // [sp+50h] [bp-20h]@4
  __int64 v11; // [sp+58h] [bp-18h]@4
  __int64 v12; // [sp+60h] [bp-10h]@4
  __int64 v13; // [sp+68h] [bp-8h]@1

  v13 = *MK_FP(__FS__, 40LL);
  puts("Let us play a game?");
  puts("you have six chances to input");
  puts("Come on!");
  v3 = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  for ( i = 0; i <= 5; ++i )
  {
    printf("%s", 4197072LL, (unsigned int)i);
    __isoc99_scanf(4197083LL, (char *)&v3 + 4 * i);
  }
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  for ( j = 0; j <= 4; j += 2 )
  {
    dword_601078 = *((_DWORD *)&v3 + j);
    dword_60107C = *((_DWORD *)&v3 + j + 1);
    sub_400686(6295672LL, 6295648LL);
    *((_DWORD *)&v8 + j) = dword_601078;
    *((_DWORD *)&v8 + j + 1) = dword_60107C;
  }
  if ( (unsigned int)sub_400770((__int64)&v8) != 1 )
  {
    puts("NO NO NO~ ");
    exit(0);
  }
  puts("Congratulation!\n");
  puts("You seccess half\n");
  puts("Do not forget to change input to hex and combine~\n");
  puts("ByeBye");
  return 0LL;
}
~~~

输入6个数字放在v3，v8还是v3，sub_400770(v8）==1

~~~c
signed __int64 __fastcall sub_400770(__int64 a1)
{
  signed __int64 result; // rax@7

  if ( *(_DWORD *)(a1 + 8) - *(_DWORD *)(a1 + 12) != 2225223423LL
    || *(_DWORD *)(a1 + 12) + *(_DWORD *)(a1 + 16) != 4201428739LL
    || *(_DWORD *)(a1 + 8) - *(_DWORD *)(a1 + 16) != 1121399208LL )
  {
    puts("Wrong!");
    result = 0LL;
  }
  else if ( *(_DWORD *)a1 != -548868226 || *(_DWORD *)(a1 + 20) != -2064448480 || *(_DWORD *)(a1 + 4) != 550153460 )
  {
    puts("Wrong!");
    result = 0LL;
  }
  else
  {
    puts("good!");
    result = 1LL;
  }
  return result;
}
~~~

上z3

~~~python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from z3 import *
v8 = [0]*6

#申明未知量
v8 = [0]*6
for i in range(6):
    v8[i] = BitVec('v8['+str(i)+']',64)
s=Solver() # 创建约束求解器

# 添加约束条件
s.add(v8[2]-v8[3]==2225223423)
s.add(v8[3]+v8[4]==4201428739)
s.add(v8[2]-v8[4]==1121399208)
s.add(v8[0]==0xDF48EF7E)
s.add(v8[5]==0x84F30420)
s.add(v8[1]== 550153460)
# 检查是否有解
if s.check()!=sat:
    print( "unsat")

m=s.model()
for d in m.decls():   # decls()返回model包含了所有符号的列表
    print("%s = %s" % (d.name(),m[d]))
"""
v8[4] = 2652626477
v8[1] = 550153460
v8[5] = 2230518816
v8[0] = 3746099070
v8[2] = 3774025685
v8[3] = 1548802262
"""
~~~

之后因为python整数范围原因位运算出错

~~~c
#include <iostream>

#pragma warning(disable:4996)
using namespace std;

int main()
{
    __int64 a[6] = { 3746099070, 550153460, 3774025685, 1548802262, 2652626477, 2230518816 };
    unsigned int a2[4] = { 2,2,3,4 };
    unsigned int v3, v4;
    int v5;
    for (int j = 0; j <= 4; j += 2) {
        v3 = a[j];
        v4 = a[j + 1];
        v5 = 1166789954*0x40;
        for (int i = 0; i <= 0x3F; ++i) {
            v4 -= (v3 + v5 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 0x10;
            v3 -= (v4 + v5 + 11) ^ ((v4 << 6) + *a2) ^ ((v4 >> 9) + a2[1]) ^ 0x20;
            v5 -= 1166789954;
        }
        a[j] = v3;
        a[j + 1] = v4;
    }
    for (int i = 0; i < 6; ++i) {
        cout<<hex<<a[i];
    }
    cout<<endl;
    

    for (int i = 0; i < 6; ++i) {
        cout << *((char*)&a[i] + 2) << *((char*)&a[i] + 1) <<  * ((char*)&a[i]);
    }

    return 0;
}
//https://www.cnblogs.com/Mayfly-nymph/p/12669358.html
~~~



## day17 5.21

### [BJDCTF2020]BJD hamburger competition

也许世上没有老八，也去人人都是老八。

ida打开后搜BJD没有。

>   unity是用C#开发。C#是微软公司发布的一种由C和C++衍生出来的面向对象的编程语言、运行于.NET Framework和.NET Core(完全开源，跨平台)之上的高级程序设计语言。
>
>   dnSpy 是一款针对 .NET 程序的逆向工程工具。

~~~c#
if (ButtonSpawnFruit.Sha1(str) == "DD01903921EA24941C26A48F2CEC24E0BB0E8CC7")
{
	this.result = "BJDCTF{" + ButtonSpawnFruit.Md5(str) + "}";
	Debug.Log(this.result);
}
~~~

1001

b8c37e33defde51cf91e1e03e51657da

b8c37e33defde51cf91e

万万没想到是大写困扰了我。

## day18 5.22

~~EPIC,永远的神~~

### usualcrypt

32位

sub_403CF8是printf

sub_401080看着是base64，flag base64后传到v5

byte_40E0E4：

~~~c
.data:0040E0E4 byte_40E0E4     db 7Ah                  ; DATA XREF: _main+5Cr
.data:0040E0E4                                         ; _main:loc_401238o
.data:0040E0E5 aMxhz3tignxlxjh db 'MXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9',0
~~~

MXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9

base64那应该改了

在sub_401000里

~~~c
signed int sub_401000()
{
  signed int result; // eax@1
  char v1; // cl@2

  result = 6;
  do
  {
    v1 = byte_40E0AA[result];
    byte_40E0AA[result] = byte_40E0A0[result];
    byte_40E0A0[result++] = v1;
  }
  while ( result < 15 );
  return result;
}
~~~

~~~c
#include <stdio.h>
#include <iostream>
using namespace std;

int main(){
    char A0[100]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    signed int result; // eax@1
    char v1; // cl@2
    result = 6;
    do
    {
        v1 = A0[result+10];
        A0[result+10] = A0[result];
        A0[result] = v1;
        result++;
    }
    while ( result < 15 );
    cout<<A0<<endl;

    return 0;

}
~~~

注意byte_40E0A0和byte_40E0AA是挨着的。[byte_40E0AA]就是[byte_40E0A0+10]

ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/

sub_401030里大小写转换

~~~c
if ( v2 < 97 || v2 > 122 )                // 97-122小写
                                                // 
      {
        if ( v2 < 65 || v2 > 90 )
          goto LABEL_9;
        LOBYTE(result) = result + 32;
      }
      else
      {
        LOBYTE(result) = result - 32;
      }
~~~

所以flag，base64--byte_40E0AA--大小写

MXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9

~~~python
import base64
n="ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/"
o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
dic=dict(zip(n,o))
#print dic
flag=''
a="zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9"
f=list(a)
for i in range(len(f)):
    if f[i]<'a' or f[i]>'z':
        if f[i]>'A' and f[i]<'Z':
            f[i]=chr(ord(f[i])+32)
    else:
        f[i]=chr(ord(f[i])-32)
for i in f:
    flag+=dic[i]
print base64.b64decode(flag)

~~~

真好flag{bAse64_2Y_a_Surprise}

为什么不对？？？

我的大小写好像有问题

~~~python
if f[i]>'A' and f[i]<'Z': #没=
~~~



## day19 5.23

### [FlareOn4]IgniteMe

~~~c
void __noreturn start()
{
  DWORD NumberOfBytesWritten; // [sp+0h] [bp-4h]@1

  NumberOfBytesWritten = 0;
  hFile = GetStdHandle(0xFFFFFFF6);
  dword_403074 = GetStdHandle(0xFFFFFFF5);
  WriteFile(dword_403074, aG1v3M3T3hFl4g, 0x13u, &NumberOfBytesWritten, 0);
  sub_4010F0();
  if ( sub_401050(NumberOfBytesWritten) )
    WriteFile(dword_403074, aG00dJ0b, 0xAu, &NumberOfBytesWritten, 0);
  else
    WriteFile(dword_403074, aN0tT00H0tRWe_7, 0x24u, &NumberOfBytesWritten, 0);
  ExitProcess(0);
}
~~~

sub_4010F0把flag放到byte_403078

~~~c
signed int sub_401050()
{
  int v0; // ST04_4@1
  int i; // [sp+4h] [bp-8h]@1
  unsigned int j; // [sp+4h] [bp-8h]@4
  char v4; // [sp+Bh] [bp-1h]@1

  v0 = sub_401020(byte_403078);
  v4 = sub_401000();
  for ( i = v0 - 1; i >= 0; --i )
  {
    byte_403180[i] = v4 ^ byte_403078[i];
    v4 = byte_403078[i];
  }
  for ( j = 0; j < 0x27; ++j )
  {
    if ( byte_403180[j] != (unsigned __int8)byte_403000[j] )
      return 0;
  }
  return 1;
}
~~~

v0是flag长度

v4：

~~~c
__int16 sub_401000()
{
  int v0; // eax@1

  v0 = __ROL4__(-2147024896, 4);
  return (unsigned __int16)v0 >> 1;
}
~~~

ROL4没查到，但v4可以调出来，为4

![](%5BFlareOn4%5DIgniteMe/Snipaste_2020-05-23_17-03-35.png)

byte_403000里

~~~c
.data:00403000 byte_403000     db 0Dh                 
.data:00403001                 db  26h ; &
.data:00403002                 db  49h ; I
.data:00403003                 db  45h ; E
.data:00403004                 db  2Ah ; *
.data:00403005                 db  17h
.data:00403006                 db  78h ; x
.data:00403007                 db  44h ; D
.data:00403008                 db  2Bh ; +
.data:00403009                 db  6Ch ; l
.data:0040300A                 db  5Dh ; ]
.data:0040300B                 db  5Eh ; ^
.data:0040300C                 db  45h ; E
.data:0040300D                 db  12h
.data:0040300E                 db  2Fh ; /
.data:0040300F                 db  17h
.data:00403010                 db  2Bh ; +
.data:00403011                 db  44h ; D
.data:00403012                 db  6Fh ; o
.data:00403013                 db  6Eh ; n
.data:00403014                 db  56h ; V
.data:00403015                 db    9
.data:00403016                 db  5Fh ; _
.data:00403017                 db  45h ; E
.data:00403018                 db  47h ; G
.data:00403019                 db  73h ; s
.data:0040301A                 db  26h ; &
.data:0040301B                 db  0Ah
.data:0040301C                 db  0Dh
.data:0040301D                 db  13h
.data:0040301E                 db  17h
.data:0040301F                 db  48h ; H
.data:00403020                 db  42h ; B
.data:00403021                 db    1
.data:00403022                 db  40h ; @
.data:00403023                 db  4Dh ; M
.data:00403024                 db  0Ch
.data:00403025                 db    2
.data:00403026                 db  69h ; i
.data:00403027                 db    0
~~~



~~~python
b= [0x0D,0x26,0x49,0x45,0x2A,0x17,0x78,0x44,0x2B,0x6C,0x5D,0x5E,0x45,0x12,0x2F,0x17,0x2B,0x44,0x6F,0x6E,0x56,0x09,0x5F,0x45,0x47,0x73,0x26,0x0A,0x0D,0x13,0x17,0x48,
0x42,0x01,0x40,0x4D,0x0C,0x02,0x69]
v=4
flag=''

for i in range(0x27-1,-1,-1):
    flag+=chr(v^b[i])
    v=v^b[i]
print flag[-1::-1]
~~~

### rome

32位无壳

falg16位，变换

~~~c
for ( i = 0; i <= 15; ++i )
              {
                if ( *((_BYTE *)&v1 + i) > '@' && *((_BYTE *)&v1 + i) <= 'Z' )
                  *((_BYTE *)&v1 + i) = (*((_BYTE *)&v1 + i) - 51) % 26 + 65;
                if ( *((_BYTE *)&v1 + i) > '`' && *((_BYTE *)&v1 + i) <= 'z' )
                  *((_BYTE *)&v1 + i) = (*((_BYTE *)&v1 + i) - 79) % 26 + 97;
              }
~~~



后为

~~~c
  v15 = 81;
  v16 = 115;
  v17 = 119;
  v18 = 51;
  v19 = 115;
  v20 = 106;
  v21 = 95;
  v22 = 108;
  v23 = 122;
  v24 = 52;
  v25 = 95;
  v26 = 85;
  v27 = 106;
  v28 = 119;
  v29 = 64;
  v30 = 108;
~~~

## day20 5.24

gkctf的签到

## day21 5.25

### [19红帽]xx

无壳64

sub_1400011A0

code是qwertyuiopasdfghjklzxcvbnm1234567890

v3=len(code)=19

v4=sub_140001620(5) molloc(5)

v5 = *(_QWORD *)&::Code;
v6 = v4
v7 = 0;
v8 = v4



最下面的的比较

v24 = (_BYTE *)v19 - (_BYTE *)&v30;

if ( *((_BYTE *)&v30 + v25) != *((_BYTE *)&v30 + v25 + v24) )

所以&v30=&v19



异或

~~~c
  for ( *((_BYTE *)v19 + 23) = *((_BYTE *)v18 + 21); v20 < v17; ++v21 )
  {
    v22 = 0i64;
    if ( v20 / 3 > 0 )
    {
      v23 = *(_BYTE *)v21;
      do
      {
        v23 ^= *((_BYTE *)v19 + v22++);
        *(_BYTE *)v21 = v23;
      }
      while ( v22 < v20 / 3 );
    }
  ++v20;
  }
~~~

sub_140001AB0里是xxtea

~~~c
*(v34 - 1) += ((v27 ^ v38) + (v29 ^ v18[v39])) ^ ((16 * v29 ^ (v38 >> 3)) + ((v29 >> 5) ^ 4 * v38));
~~~

和下面一样

~~~
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
~~~

知识点里xxtea是纯数字的，后来找到了https://blog.csdn.net/cserchen/article/details/8238641 python实现的字符串加解密。

~~~python
import binascii
result = 'CEBC406B7C3A95C0EF9B202091F70235231802C8E75656FA'

data=[0]*(len(result)/2)
for i in range(0,len(result),2):
    data[i/2]=int(('0x'+result[i]+result[i+1]),16)
#print len(data)

for i in range(len(data)-1,-1,-1):
    for j in range(i//3):
        data[i] ^= data[j]

h = [2,0,3,1,6,4,7,5,10,8,11,9,14,12,15,13,18,16,19,17,22,20,23,21]
c = [1]*24
for i in range(24):
    c[h[i]] = data[i]
print(c)
cc=''
for i in c:
    #确保两位
    if i<16:
        cc+='0' 
    cc+=str(hex(i)).replace('0x','')

print cc
print len(cc)
strc=binascii.a2b_hex(cc) 
   
############################################################  
#                                                          #  
# The implementation of PHPRPC Protocol 3.0                #  
#                                                          #  
# xxtea.py                                                 #  
#                                                          #  
# Release 3.0.0                                            #  
# Copyright (c) 2005-2008 by Team-PHPRPC                   #  
#                                                          #  
# WebSite:  http://www.phprpc.org/                         #  
#           http://www.phprpc.net/                         #  
#           http://www.phprpc.com/                         #  
#           http://sourceforge.net/projects/php-rpc/       #  
#                                                          #  
# Authors:  Ma Bingyao <andot@ujn.edu.cn>                  #  
#                                                          #  
# This file may be distributed and/or modified under the   #  
# terms of the GNU Lesser General Public License (LGPL)    #  
# version 3.0 as published by the Free Software Foundation #  
# and appearing in the included file LICENSE.              #  
#                                                          #  
############################################################  
#  
# XXTEA encryption arithmetic library.  
#  
# Copyright (C) 2005-2008 Ma Bingyao <andot@ujn.edu.cn>  
# Version: 1.0  
# LastModified: Oct 5, 2008  
# This library is free.  You can redistribute it and/or modify it.  
  
import struct  
  
_DELTA = 0x9E3779B9  
  
def _long2str(v, w):  
    n = (len(v) - 1) << 2  
    if w:  
        m = v[-1]  
        if (m < n - 3) or (m > n): return ''  
        n = m  
    s = struct.pack('<%iL' % len(v), *v)  
    return s[0:n] if w else s  
  
def _str2long(s, w):  
    n = len(s)  
    m = (4 - (n & 3) & 3) + n  
    s = s.ljust(m, "\0")  
    v = list(struct.unpack('<%iL' % (m >> 2), s))  
    if w: v.append(n)  
    return v  
  
def encrypt(str, key):  
    if str == '': return str  
    v = _str2long(str, True)  
    k = _str2long(key.ljust(16, "\0"), False)  
    n = len(v) - 1  
    z = v[n]  
    y = v[0]  
    sum = 0  
    q = 6 + 52 // (n + 1)  
    while q > 0:  
        sum = (sum + _DELTA) & 0xffffffff  
        e = sum >> 2 & 3  
        for p in xrange(n):  
            y = v[p + 1]  
            v[p] = (v[p] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff  
            z = v[p]  
        y = v[0]  
        v[n] = (v[n] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z))) & 0xffffffff  
        z = v[n]  
        q -= 1  
    return _long2str(v, False)  
  
def decrypt(str, key):  
    if str == '': return str  
    v = _str2long(str, False)  
    k = _str2long(key.ljust(16, "\0"), False)  
    n = len(v) - 1  
    z = v[n]  
    y = v[0]  
    q = 6 + 52 // (n + 1)  
    sum = (q * _DELTA) & 0xffffffff  
    while (sum != 0):  
        e = sum >> 2 & 3  
        for p in xrange(n, 0, -1):  
            z = v[p - 1]  
            v[p] = (v[p] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff  
            y = v[p]  
        z = v[n]  
        v[0] = (v[0] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[0 & 3 ^ e] ^ z))) & 0xffffffff  
        y = v[0]  
        sum = (sum - _DELTA) & 0xffffffff  
    return _long2str(v, True)  
  

key = 'flag'
flag = decrypt(strc, key)
print flag


~~~



## day22 5.27

### [MRCTF2020]Transform

64无壳

简单的转换

~~~c
__int64 sub_401530()
{
  char Str[104]; // [sp+20h] [bp-70h]@1
  int j; // [sp+88h] [bp-8h]@7
  int i; // [sp+8Ch] [bp-4h]@4

  sub_402230();
  printf("Give me your code:\n");
  scanf("%s", Str);
  if ( strlen(Str) != 33 )
  {
    printf("Wrong!\n");
    system("pause");
    exit(0);
  }
  for ( i = 0; i <= 32; ++i )
  {
    byte_414040[i] = Str[dword_40F040[i]];
    byte_414040[i] ^= LOBYTE(dword_40F040[i]);
  }
  for ( j = 0; j <= 32; ++j )
  {
    if ( byte_40F0E0[j] != byte_414040[j] )
    {
      printf("Wrong!\n");
      system("pause");
      exit(0);
    }
  }
  printf("Right!Good Job!\n");
  printf("Here is your flag: %s\n");
  system("pause");
  return 0i64;
}
~~~



输入str，33位

 byte_414040[i] = Str[dword_40F040[i]];

byte_414040[i] ^= LOBYTE(dword_40F040[i]);

LOBYTE()得到一个16bit数最低（最右边）那个字节,用&0xff就好。

~~~c
.data:000000000040F040 dword_40F040    dd 9, 0Ah, 0Fh, 17h, 7, 18h, 0Ch, 6, 1, 10h, 3, 11h, 20h
.data:000000000040F040                                         ; DATA XREF: sub_401530+79o
.data:000000000040F040                                         ; sub_401530+B8o
.data:000000000040F040                 dd 1Dh, 0Bh, 1Eh, 1Bh, 16h, 4, 0Dh, 13h, 14h, 15h, 2, 19h
.data:000000000040F040                 dd 5, 1Fh, 8, 12h, 1Ah, 1Ch, 0Eh, 8 dup(0)
~~~



~~~
.data:000000000040F0E0 byte_40F0E0     db 67h, 79h, 7Bh, 7Fh, 75h, 2Bh, 3Ch, 52h, 53h, 79h, 57h
.data:000000000040F0E0                                         ; DATA XREF: sub_401530+EFo
.data:000000000040F0E0                 db 5Eh, 5Dh, 42h, 7Bh, 2Dh, 2Ah, 66h, 42h, 7Eh, 4Ch, 57h
.data:000000000040F0E0                 db 79h, 41h, 6Bh, 7Eh, 65h, 3Ch, 5Ch, 45h, 6Fh, 62h, 4Dh
.data:000000000040F0E0                 db 3Fh dup(0)
~~~

~~~python
a='9, 0Ah, 0Fh, 17h, 7, 18h, 0Ch, 6, 1, 10h, 3, 11h, 20h,1Dh, 0Bh, 1Eh, 1Bh, 16h, 4, 0Dh, 13h, 14h, 15h, 2, 19h,5, 1Fh, 8, 12h, 1Ah, 1Ch, 0Eh, 0'
eflag='67h, 79h, 7Bh, 7Fh, 75h, 2Bh, 3Ch, 52h, 53h, 79h, 57h,5Eh, 5Dh, 42h, 7Bh, 2Dh, 2Ah, 66h, 42h, 7Eh, 4Ch, 57h,79h, 41h, 6Bh, 7Eh, 65h, 3Ch, 5Ch, 45h, 6Fh, 62h, 4Dh'
flag=[0]*33

base=a.split(',')
for i in range(len(base)):
    base[i]=int(('0x'+base[i]).replace('h','').replace(' ',''),16)
print len(base)

ef=eflag.split(',')
for i in range(len(ef)):
    ef[i]=int(('0x'+ef[i]).replace('h','').replace(' ',''),16)
print len(ef)


for i in range(33):
    flag[base[i]]=ef[i]^base[i]
s=''
for i in flag:
    s+=chr(i)
print s

~~~

### [HDCTF2019]Maze

Maze迷宫，junk是废物垃圾，感觉是要找东西。

有壳

迷宫是

~~~
*******+********* ******    ****   ******* **F******    **************
~~~

后面写了7，所以要吗7要么10

~~~python
maze='*******+********* ******    ****   ******* **F******    **************'
print len(maze)
a=0
f=''
for i in maze:
    a+=1
    if i==' ':
        f+='='
    else:
        f+=i
    if a%10==0:
        f+='\n'
print f

~~~

~~~
70
*******+**
*******=**
****====**
**===*****
**=**F****
**====****
**********
~~~

下下左左左下左左下下右右右上

emmmm，flag{ssaaasaassdddw}

main函数奇怪数据强制转换

~~~
.text:0040102C                 jnz     short near ptr byte_40102F
.text:0040102C ; ---------------------------------------------------------------------------
.text:0040102E                 db 0E8h
.text:0040102F byte_40102F     db 58h                  ; CODE XREF: .text:0040102Cj
.text:00401030                 dd 0EC45C7h
.text:00401034                 db 2 dup(0)
.text:00401036 ; ---------------------------------------------------------------------------
.text:00401036                 add     bl, ch
.text:00401038
.text:00401038 loc_401038:                             ; CODE XREF: .text:loc_4010B4j
~~~

>   花指令是，由[设计者](https://baike.baidu.com/item/设计者/514381)特别构思，希望使[反汇编](https://baike.baidu.com/item/反汇编/10858476)的时候出错，让破解者无法清楚正确地[反汇编程序](https://baike.baidu.com/item/反汇编程序)的内容，迷失方向。经典的是，目标位置是另一条指令的中间，这样在反汇编的时候便会出现混乱。花指令有可能利用各种指令：[jmp](https://baike.baidu.com/item/jmp/2149772), call, ret的一些[堆栈](https://baike.baidu.com/item/堆栈/1682032)技巧，位置运算，等等。



~~~
  for ( i = 0; i <= 13; ++i )
  {
    switch ( v5[i] )
    {
      case 'w':
        ++dword_40807C;
        break;
      case 's':
        --dword_40807C;
        break;
      case 'a':
        --dword_408078;
        break;
      case 'd':
        ++dword_408078;
        break;
      default:
        continue;
    }
  }
~~~

od nop

保存文件。

洗衣服啊啊啊。

## day23 5.29

### [WUSTCTF2020]level1

有个output

~~~
  stream = fopen("flag", "r");
  fread(ptr, 1uLL, 0x14uLL, stream);
  fclose(stream);
  for ( i = 1; i <= 19; ++i )
  {
    if ( i & 1 )
      printf("%ld\n", (unsigned int)(ptr[i] << i));
    else
      printf("%ld\n", (unsigned int)(i * ptr[i]));
  }
~~~

flag19位

~~~py
a='''222
198
232
816
200
1536
300
6144
984
51200
570
92160
1200
565248
756
1474560
800
6291456
1782
65536000
'''
b=a.split('\n')
flag=''
for i in range(1,20):
    print b[i]
    if i&1:
        print ("aa",int(b[i],10)>>i)
        flag+=chr(int(b[i],10)>>i)
    else:
        print("bb",int(b[i],10)//i)
        flag+=chr(int(b[i],10)//i)
print flag
~~~

观察一下数据，随便填一个数。

### [安洵杯 2019]crackMe

>    Hook 技术又叫做钩子函数，在系统没有调用该函数之前，钩子程序就先捕获该消息，钩子函数先得到控制权，这时钩子函数既可以加工处理（改变）该函数的执行行为，还可以强制结束消息的传递。

比较

~~~
  if ( !j_strcmp(Str1, Str2) )
  {
    v0 = printf("right\n");
    sub_4111A4(&v3 == &v3, v0);
  }
~~~

找到str、str1、str2

~~~c
Str             db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
Str2            db '1UTAOIkpyOSWGv/mOYFY4R!!'
~~~



~~~c
    for ( i = 0; ; i += 2 )
    {
      v1 = j_strlen(Str2);
      if ( i >= v1 )
        break;
      v4 = Str2[i];
      Str2[i] = Str2[i + 1];
      Str2[i + 1] = v4;
    }
~~~

str2奇偶交换

~~~c
Str1 = (char *)sub_41126C(byte_41A180);
~~~

sub_41126C应该是base64。

我想着是flag base64后奇偶交换变成str2。然而并不是。再看看。

搜hooked

首先Str大小写转换

~~~c
  for ( i = 0; ; ++i )
  {
    v4 = j_strlen(Str);
    if ( i >= v4 )
      break;
    v10 = Str[i] >= 97;
    v9 = Str[i] <= 122;
    if ( v9 & v10 )
    {
      Str[i] -= 32;
    }
    else
    {
      v10 = Str[i] >= 65;
      v9 = Str[i] <= 90;
      if ( v9 & v10 )
        Str[i] += 32;
    }
  }
~~~

然后AddVectoredExceptionHandler，这是什么

>   向量化异常处理（Vectored Exception Handling）
>   向量化异常处理(VEH)是结构化异常处理的一个扩展，它在Windows XP中被引入。
>
>   你可以使用AddVectoredExceptionHandler()函数添加一个向量化异常处理器，VEH的缺点是它只能用在WinXP及其以后的版本，因此需要在运行时检查AddVectoredExceptionHandler()函数是否存在。
>
>   要移除先前安装的异常处理器，可以使用RemoveVectoredExceptionHandler()函数。
>
>   VEH允许查看或处理应用程序中所有的异常。为了保持后向兼容，当程序中的某些部分发生SEH异常时，系统依次调用已安装的VEH处理器，直到它找到有用的SEH处理器。
>
>   VEH的一个优点是能够链接异常处理器(chain exception handlers)，因此如果有人在你之前安装了向量化异常处理器，你仍然能截获这些异常。
>
>   当你需要像调试器一样监事所有的异常时，使用VEH是很合适的。问题是你需要决定哪个异常需要处理，哪个异常需要跳过。 In program's code, some exceptions may be intentionally guarded by __try{}__except(){} construction, and handling such exceptions in VEH and not passing it to frame-based SEH handler, you may introduce bugs into application logics.
>
>   VEH目前没有被CrashRpt所使用。SetUnhandledExceptionFilter()更加适用，因为它是top-level SEH处理器。如果没有人处理异常，top-level SEH处理器就会被调用，并且你不用决定是否要处理这个异常。

翻译的。

~~~
v6 = (int)AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)Handler);
~~~
Handler进去提示where_are_you_now后一个

sub_411172

~~~c
while ( v8 < 0x20 )
  {
    v13[v8] = *(&v9 + v8) ^ sub_4114E0(dword_417A78[v8] ^ *(&v12 + v8) ^ *(&v11 + v8) ^ *(&v10 + v8));
    *(_DWORD *)(a1 + 4 * v8) = v13[v8];
    v4 = v8++ + 1;
  }
~~~

看了wp后知道sm4，。。。我好像学了

key就是where_are_you_now？



那个base64最后有一个return (a1 + 24) % 64;









~~~python
from pysm4 import *
import base64
import binascii
key="where_are_u_now?"
key= binascii.b2a_hex(key)
print key
b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
a="1UTAOIkpyOSWGv/mOYFY4R!!"
ba64=''
for i in range(len(b64)):
    x=b64[(i+24)%64]
    if 'a'<=x<='z':
        ba64+=x.upper()
    elif 'A'<=x<='Z':
        ba64+=x.lower()
    else:
        ba64+=x
print ba64

b=list(a)
cflag=''
for i in range(0,len(b)-2,2):
    cflag+=b64[ba64.find(b[i+1])]
    cflag+=b64[ba64.find(b[i])]
cflag+='=='
print cflag

cc= base64.b64decode(cflag)
c=''
for i in cc:
    if ord(i)<=0xf:
        c+='0'
    c+=str(hex(ord(i))).replace("0x",'')
print c


c = 0x59d095290df2400614f48d276906874e
key=0x77686572655f6172655f755f6e6f773f
          
flag = decrypt(c, key)
flag=hex(flag)[2:].replace('L', '')
print binascii.a2b_hex(str(flag))

~~~

写的我吐了。各种格式啊什么东西的

其中[pysm4](https://github.com/yang3yen/pysm4),要看看他的使用

## day24 5.30

### eqution

看源代码解JSfuck

本来想http://ctf.ssleye.com/jsfuck.html解密的，但它的代码是部分部分加密的，一个一个找眼都瞎啦。去找代码。本来想搞个python爬虫，结果burpsuit用不了。

~~~javascript
<script>
function deEquation(str) {
  for (let i = 0; i <= 1; i++) {
  str = str.replace(/l\[(\D*?)](\+l|-l|==)/g, (m, a, b) => 'l[' + eval(a) + ']' + b);
  }
  str = str.replace(/==(\D*?)&&/g, (m, a) => '==' + eval(a) + '&&');
  return str;
}
s="l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[+!+[]]])&&l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+[]]]+l[+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+[]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]+l[+[]]==+(+!+[]+[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]])&&l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]])&&l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(+!+[]+[+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+[+!+[]+[!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]-l[+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]==+(+!+[]+[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]==-+(!+[]+!+[]+!+[]+[+!+[]+[!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+[]]+l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]])&&l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]]+l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]==+(!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]+l[+!+[]+[!+[]+!+[]]]+l[+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(+!+[]+[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]+l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]]])&&l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]+l[!+[]+!+[]+!+[]+[+!+[]]]==+(+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]==+(+!+[]+[+[]+[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]])&&l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]==+(!+[]+!+[]+!+[]+[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]]+l[!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[+[]]]==-+(+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+[]]-l[!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]]==-+(!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[+[]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+[+!+[]+[!+[]+!+[]+!+[]]])&&l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]+l[!+[]+!+[]+!+[]]==-+(!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]-l[+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]+l[+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]])&&l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]+l[+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]+l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+[+!+[]+[!+[]+!+[]]])&&l[+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]-l[+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]])&&l[!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[+!+[]]]-l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]]-l[+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[+!+[]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]+l[+[]]+l[!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==+(+!+[]+[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]])&&l[+!+[]+[!+[]+!+[]+!+[]]]+l[+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]==-+(+!+[]+[!+[]+!+[]+[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]])&&l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[+!+[]]]+l[+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]==-+(+!+[]+[+!+[]+[!+[]+!+[]+!+[]+!+[]]])&&l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]+l[+!+[]+[+!+[]]]+l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]+l[+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+[+[]]])&&l[+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]-l[+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]]+l[+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+!+[]+[+!+[]+[!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]+l[!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+[]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+!+[]+[+[]+[!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]])&&l[+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+[]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[+!+[]]-l[!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(!+[]+!+[]+!+[]+!+[]+!+[]+[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]])&&l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+!+[]]]-l[!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[+[]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]+l[!+[]+!+[]+[+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]==-+(+!+[]+[!+[]+!+[]])&&l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+[+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]]]-l[+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]]]-l[!+[]+!+[]+!+[]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]-l[!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]]]+l[+!+[]]-l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+[+!+[]]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[+!+[]+[+[]]]-l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+[!+[]+!+[]]]+l[!+[]+!+[]+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]+l[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]+l[+!+[]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]]]-l[!+[]+!+[]+!+[]+[+!+[]]]==+(!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+[+!+[]])";
ss=deEquation(s);
document.write(ss);
</script>
~~~

## day25 5.31

### [WUSTCTF2020]level2

有壳，命令行upx -d脱壳，不知道为什么图形界面不行。

wctf2020{Just_upx_-d}

好，这题目，好。

### [FlareOn6]Overlong

无壳。找东西。

提示i nerver broke the encoding.

unk_402008有奇怪的数据，可能是flag

~~~c
v4 = sub_401160((int)Text, (int)&qiguai, 28u);
~~~

28位。

text128位。

a3是28。

~~~
  for ( i = 0; ; ++i )
  {
    if ( i < a3 )
    {
      a2 += sub_401000(a1, a2);
      v3 = *(_BYTE *)a1++;
      if ( v3 )
        continue;
    }
    break;
  }
~~~

结合提示，去改a3.

~~~
.text:004011C9                 push    1Ch
~~~

改成qiguai的长度，20b6-2008+1=af

在od改1c为af时改了很多次，发现如果要改成两位数字或一位数字+一位字母可以，而两位字母不可以，加0后如果：

push 0aa

~~~c
00CC11C9     68 AA000000    PUSH 0AA
~~~

push 0a1a

~~~
00CC11D3     68 1A0A0000    PUSH 0A1A
~~~

push 0ffffffaf

~~~c
00CC1205     6A AF          PUSH -51
~~~

## day26 6.1+6.2

### [GWCTF 2019]re3

correct引用下面有奇怪的数据。

~~~c
void __noreturn sub_402126()
{
  signed int i; // [sp+8h] [bp-48h]@4
  char s; // [sp+20h] [bp-30h]@1
  __int64 v2; // [sp+48h] [bp-8h]@1

  v2 = *MK_FP(__FS__, 40LL);
  __isoc99_scanf(4204480LL, &s);
  if ( (unsigned int)strlen(&s) != 32 )
  {
    puts("Wrong!");
    exit(0);
  }
  mprotect((void *)0x400000, 0xF000uLL, 7);
  for ( i = 0; i <= 223; ++i )
    *((_BYTE *)sub_402219 + i) ^= 0x99u;
  sub_40207B(6304112LL, 61440LL);
  sub_402219(&s);
}
~~~

flag32位



>    在Linux中，mprotect()函数可以用来修改一段指定内存区域的保护属性。
>   函数原型如下：
>
>   ```c
>   #include <unistd.h>
>   #include <sys/mmap.h>
>   int mprotect(const void *start, size_t len, int prot);
>   ```
>
>   mprotect()函数把自start开始的、长度为len的内存区的保护属性修改为prot指定的值。
>
>   prot可以取以下几个值，并且可以用“|”将几个属性合起来使用：
>
>   1）PROT_READ：表示内存段内的内容可写；
>
>   2）PROT_WRITE：表示内存段内的内容可读；
>
>   3）PROT_EXEC：表示内存段中的内容可执行；
>
>   4）PROT_NONE：表示内存段中的内容根本没法访问。

这里7是和chmod一样可读可写可执行。

sub_402219还原idc脚本

~~~c
#include <idc.idc>

static main()
{
    auto addr = 0x402219;
    auto i = 0;
    for(i=0;i<224;i++)
    {
        PatchByte(addr+i,Byte(addr+i)^0x99);
    }
}
~~~

auto声明变量

PatchByte(long addr, long val)设置虚拟地址addr处的一个字节值。

c强制转换，p生成函数。

主函数先进入sub_40207B。

~~~c
unsigned __int64 __fastcall sub_40207B(__int64 a1)
{
  char v2; // [rsp+10h] [rbp-50h]
  __int64 v3; // [rsp+20h] [rbp-40h]
  __int64 v4; // [rsp+30h] [rbp-30h]
  __int64 v5; // [rsp+40h] [rbp-20h]
  unsigned __int64 v6; // [rsp+58h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  sub_401CF9(&unk_603120, 64LL, &v2);
  sub_401CF9(&unk_603100, 20LL, &v3);
  sub_401CF9(&unk_6030C0, 53LL, &v4);
  sub_401CF9(&dword_4025C0, 256LL, &v5);
  sub_401CF9(&v2, 64LL, a1);
  return __readfsqword(0x28u) ^ v6;
}
~~~

__readfsqword从相对于 FS 段开头的偏移量指定的位置读取内存。

sub_401CF9是md5， 从 v6 = 0x67452301v7 = 0xEFCDAB89;v8 = 0x98BADCFE; v9 = 0x10325476;可以看出来。其中起到作用的是

~~~c
sub_401CF9(&unk_603120, 64LL, &v2);
sub_401CF9(&v2, 64LL, a1);
~~~

unk_603120是base64表，a1是unk_603170地址，结果就是base64表两次md5返回unk_603170。

base64表两次md5不行，可能改了什么，用od结果为cb8d493521b47a4cc1ae7e62229266ce。

[看过feng_2016的wp发现sub_40207B中4个md5的关系](https://blog.csdn.net/feng_2016/article/details/106358117?fps=1&locationNum=2)

>   ~~~python
>   import hashlib
>   s1 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
>   s2 = b'\x00\x00\x00\x00\x96\x30\x07\x77\x2C\x61\x0E\xEE\xBA\x51\x09\x99\x19\xC4\x6D\x07'
>   s3 = b'\x03\x05\x07\x0B\x0D\x11\x13\x17\x1D\x1F\x25\x29\x2B\x2F\x35\x3B\x3D\x43\x47\x49\x4F\x53\x59\x61\x65\x67\x6B\x6D\x71\x7F\x83\x89\x8B\x95\x97\x9D\xA3\xA7\xAD\xB3\xB5\xBF\xC1\xC5\xC7\xD3\xDF\xE3\xE5\xE9\xEF\xF1\xFB'
>   s4 = b'\x78\xA4\x6A\xD7\x56\xB7\xC7\xE8\xDB\x70\x20\x24\xEE\xCE\xBD\xC1\xAF\x0F\x7C\xF5\x2A\xC6\x87\x47\x13\x46\x30\xA8\x01\x95\x46\xFD\xD8\x98\x80\x69\xAF\xF7\x44\x8B\xB1\x5B\xFF\xFF\xBE\xD7\x5C\x89\x22\x11\x90\x6B\x93\x71\x98\xFD\x8E\x43\x79\xA6\x21\x08\xB4\x49\x62\x25\x1E\xF6\x40\xB3\x40\xC0\x51\x5A\x5E\x26\xAA\xC7\xB6\xE9\x5D\x10\x2F\xD6\x53\x14\x44\x02\x81\xE6\xA1\xD8\xC8\xFB\xD3\xE7\xE6\xCD\xE1\x21\xD6\x07\x37\xC3\x87\x0D\xD5\xF4\xED\x14\x5A\x45\x05\xE9\xE3\xA9\xF8\xA3\xEF\xFC\xD9\x02\x6F\x67\x8A\x4C\x2A\x8D\x42\x39\xFA\xFF\x81\xF6\x71\x87\x22\x61\x9D\x6D\x0C\x38\xE5\xFD\x44\xEA\xBE\xA4\xA9\xCF\xDE\x4B\x60\x4B\xBB\xF6\x70\xBC\xBF\xBE\xC6\x7E\x9B\x28\xFA\x27\xA1\xEA\x85\x30\xEF\xD4\x05\x1D\x88\x04\x39\xD0\xD4\xD9\xE5\x99\xDB\xE6\xF8\x7C\xA2\x1F\x65\x56\xAC\xC4\x44\x22\x29\xF4\x97\xFF\x2A\x43\xA7\x23\x94\xAB\x39\xA0\x93\xFC\xC3\x59\x5B\x65\x92\xCC\x0C\x8F\x7D\xF4\xEF\xFF\xD1\x5D\x84\x85\x4F\x7E\xA8\x6F\xE0\xE6\x2C\xFE\x14\x43\x01\xA3\xA1\x11\x08\x4E\x82\x7E\x53\xF7\x35\xF2\x3A\xBD\xBB\xD2\xD7\x2A\x91\xD3\x86\xEB'
>   s =''
>   a = [s1,s2,s3,s4]
>   for i in a:
>       md5 = hashlib.md5()
>       md5.update(i)
>       s += md5.hexdigest()
>   #以上步骤得到s，下面是我把它提取出来转化为二进制了
>   s = b'\x78\x45\xf7\xea\xde\x89\x33\x8a\xda\xbf\xef\x89\xbd\x6e\x9a\x5b\xe8\x4f\xed\xef\x50\x67\xcf\x85\xf5\xe4\x7f\x4f\x4b\x59\x47\xa3\xc8\x38\xba\xe0\x2e\x07\xae\x0c\x27\x6d\xfb\x2e\x53\x30\x04\xc8\x7a\xc5\xfb\xac\x91\x1f\x3b\x36\x78\x41\xf8\xdc\xec\xc9\xdb\x46'
>   md5 = hashlib.md5()
>   md5.update(s)
>   print(md5.hexdigest()
>   #得到cb8d493521b47a4cc1ae7e62229266ce
>   ————————————————
>   版权声明：本文为CSDN博主「feng_2016」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
>   原文链接：https://blog.csdn.net/feng_2016/article/details/106358117
>   ~~~



接下来就是sub_402219

看到

~~~
.rodata:00000000004023A0 ; char byte_4023A0[256]
.rodata:00000000004023A0 byte_4023A0     db 63h                  ; DATA XREF: sub_4007C6+17A↑r
.rodata:00000000004023A0                                         ; sub_4007C6+18D↑r ...
.rodata:00000000004023A1                 db  7Ch ; |
.rodata:00000000004023A2                 db  77h ; w
.rodata:00000000004023A3                 db  7Bh ; {
.rodata:00000000004023A4                 db 0F2h
.rodata:00000000004023A5                 db  6Bh ; k
.rodata:00000000004023A6                 db  6Fh ; o
~~~

是AES的s盒。

看看aes加密后和谁比，解密flag。

~~~python
from Crypto.Cipher import AES

key='CB8D493521B47A4CC1AE7E62229266CE'.decode('hex')
c='BC0AADC0147C5ECCE0B140BC9C51D52B46B2B9434DE5324BAD7FB4B39CDB4B5B'.decode('hex')
aes = AES.new(key, AES.MODE_ECB)
print(aes.decrypt(c))

~~~

## day27 6.3

### [GUET-CTF2019]number_game

~~~c
  __int64 v3; // ST08_8
  __int64 v5; // [rsp+10h] [rbp-30h]
  __int16 v6; // [rsp+18h] [rbp-28h]
  __int64 v7; // [rsp+20h] [rbp-20h]
  __int16 v8; // [rsp+28h] [rbp-18h]
  char v9; // [rsp+2Ah] [rbp-16h]
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v5 = 0LL;
  v6 = 0;
  v7 = 0LL;
  v8 = 0;
  v9 = 0;
  __isoc99_scanf("%s", &v5, a3);
  if ( (unsigned int)sub_4006D6(&v5) )
  {
    v3 = sub_400758(&v5, 0LL, 10LL);
    sub_400807(v3, &v7);
    v9 = 0;
    sub_400881(&v7);
    if ( (unsigned int)sub_400917() )
    {
      puts("TQL!");
      printf("flag{");
      printf("%s", &v5);
      puts("}");
    }
~~~

main函数里判断

+   首先对输入sub_4006D6

~~~c
  if ( strlen(a1) == 10 )
  {
    for ( i = 0; i <= 9; ++i )
    {
      if ( a1[i] > 52 || a1[i] <= 47 )
      {
        puts("Wrong!");
        return 0LL;
      }
    }
    result = 1LL;
  }
  else
  {
    puts("Wrong!");
    result = 0LL;
  }
  return result;
~~~

输入v5 10位且47<v5[i]<=52，那就是01234

+   接下来sub_400758

~~~
  v6 = a3;
  v7 = *(_BYTE *)(a2 + a1);
  if ( v7 == ' ' || v7 == '\n' || a2 >= a3 )
    return 0LL;
  v4 = malloc(0x18uLL);
  v5 = v4;
  *(_BYTE *)v4 = v7;
  v4[1] = sub_400758(a1, 2 * a2 + 1, v6);
  v5[2] = sub_400758(a1, 2 * (a2 + 1), v6);
  return v5;
~~~

v3赋值

+   sub_400807

~~~c
__int64 __fastcall sub_400807(__int64 a1, __int64 a2)
{
  __int64 result; // rax

  result = a1;
  if ( a1 )
  {
    sub_400807(*(_QWORD *)(a1 + 8), a2);
    *(_BYTE *)(a2 + dword_601080++) = *(_BYTE *)a1;
    result = sub_400807(*(_QWORD *)(a1 + 16), a2);
  }
  return result;
}
~~~

v7 dword_601080赋值v3[3]、[2]、[1]、[0]（int 64）

+   sub_400881((char *)&v7);

~~~c
__int64 __fastcall sub_400881(char *a1)
{
  __int64 result; // rax

  byte_601062 = *a1;
  byte_601067 = a1[1];
  byte_601069 = a1[2];
  byte_60106B = a1[3];
  byte_60106E = a1[4];
  byte_60106F = a1[5];
  byte_601071 = a1[6];
  byte_601072 = a1[7];
  byte_601076 = a1[8];
  result = (unsigned __int8)a1[9];
  byte_601077 = a1[9];
  return result;
}
~~~

将v7分别赋值

+   sub_400917判断

~~~c
__int64 sub_400917()
{
  unsigned int v1; // [rsp+0h] [rbp-10h]
  signed int i; // [rsp+4h] [rbp-Ch]
  signed int j; // [rsp+8h] [rbp-8h]
  int k; // [rsp+Ch] [rbp-4h]

  v1 = 1;
  for ( i = 0; i <= 4; ++i )
  {
    for ( j = 0; j <= 4; ++j )
    {
      for ( k = j + 1; k <= 4; ++k )
      {
        if ( *((_BYTE *)&unk_601060 + 5 * i + j) == *((_BYTE *)&unk_601060 + 5 * i + k) )
          v1 = 0;
        if ( *((_BYTE *)&unk_601060 + 5 * j + i) == *((_BYTE *)&unk_601060 + 5 * k + i) )
          v1 = 0;
      }
    }
  }
  return v1;
}
~~~

数独解出来v7=0,4,2,1,4,2,1,4,3,0

linux ida远程调试，我行你也行。（注意版本）

## day28 6.5

### [2019红帽杯]childRE

31位

~~~c
  sub_140001080("%s", &v13);
  v0 = -1i64;
  do
    ++v0;
  while ( *((_BYTE *)&v13 + v0) );
  if ( v0 != 31 )
  {
    while ( 1 )
      Sleep(0x3E8u);
  }
~~~

注意

~~~
.rdata:0000000140003438 a55565653255552 db '55565653255552225565565555243466334653663544426565555525555222',0
.rdata:0000000140003477                 align 8
.rdata:0000000140003478 a46200860044218 db '(_@4620!08!6_0*0442!@186%%0@3=66!!974*3234=&0^3&1@=&0908!6_0*&',0
~~~



~~~c
    do
    {
      v11 = outputString[v10];
      v12 = v11 % 23;
      if ( a1234567890Qwer[v12] != *(_BYTE *)(v10 + 0x140003478i64) )
        _exit(v9);
      if ( a1234567890Qwer[v11 / 23] != *(_BYTE *)(v10 + 0x140003438i64) )
        _exit(v9 * v9);
      ++v9;
      ++v10;
    }
    while ( v9 < 62 );
~~~

相当于

~~~
a[o[i]%23]=str78[i]
a[o[i]/23] =str38[i]
0<i<62
~~~

~~~python
"""
a[o[i]%23]=str78[i]
a[o[i]/23] =str38[i]
"""
o=""
str38="55565653255552225565565555243466334653663544426565555525555222"
str78="(_@4620!08!6_0*0442!@186%%0@3=66!!974*3234=&0^3&1@=&0908!6_0*&"
a="1234567890-=!@#$%^&*()_+qwertyuiop[]QWERTYUIOP{}asdfghjkl;"+chr(0x27)+"A"
for i in range(62):
    m=a.find(str78[i]) 
    n =a.find(str38[i])
    o+=chr(n*23+m)
print(o) 
#private: char * __thiscall R0Pxx::My_Aut0_PWN(unsigned char *)
~~~

看UnDecorateSymbolName，看了百度看不懂，[C++ 符号修饰和函数签名](https://www.cnblogs.com/wfwenchao/articles/4140388.html)

~~~
UnDecorateSymbolName(v2, outputString, 0x100u, 0);
~~~

>   UnDecorateSymbolName [函数](https://baike.baidu.com/item/函数/18686609)反修饰指定已修饰的 C++ 符号名。
>
>   ~~~c
>   DWORD WINAPI UnDecorateSymbolName(
>     _In_ PCTSTR DecoratedName,
>     _Out_ PTSTR UnDecoratedName,
>     _In_ DWORD UndecoratedLength,
>     _In_ DWORD Flags
>   );
>   ~~~
>
>   DecoratedName [输入]
>   已修饰的 C++ 符号名。此名称能以始终为问号 (?) 的首字符鉴别。
>   UnDecoratedName [输出]
>   指向字符串缓冲区的指针，该缓冲区接收未修饰的名字。
>   UndecoratedLength [输入]
>   UnDecoratedName 缓冲区的大小，为字符数。
>   Flags [输入]
>   用于反修饰已修饰名称的方式的选项。此参数能为零或更多个下列值

现在要v2的值，[C++编译时函数名修饰约定规则（很具体），MFC提供的宏，extern "C"的作用](https://www.cnblogs.com/findumars/p/5143949.html)

?My_Aut0_PWN@R0Pxx@@AAEPADPAE

用x64dbg调试

![](%5B2019%E7%BA%A2%E5%B8%BD%E6%9D%AF%5DchildRE/Snipaste_2020-06-05_21-47-36.png)

写脚本把字符串转一下得到flag，再md5.





看别人的wp中UnDecorateSymbolName可以这样，其中注意是char* My_Aut0_PWN不是char My_Aut0_PWN

[wp](https://www.cnblogs.com/jentleTao/p/12796542.html)

~~~c
#include<iostream>
#include <stdio.h>
using namespace std;

class ROPxx {
public:
    ROPxx() {
        unsigned char a;
        My_Aut0_PWN(&a);
    }

private:
    char* My_Aut0_PWN(unsigned char*) {
        printf("%s", __FUNCDNAME__);
        return 0;
    }
};
int main() {
    new ROPxx();
    getchar();
    return 0;
}
~~~

![](%5B2019%E7%BA%A2%E5%B8%BD%E6%9D%AF%5DchildRE/Snipaste_2020-06-05_17-04-13.png)

## day29 6.6

### [MRCTF2020]Xor

ida编码格式改utf-8，一开始英文乱码。

sub_401020输出

sub_401050输入

byte_4212C0输入，27位

比较函数

~~~c
  v1 = 0;
  do
  {
    if ( ((unsigned __int8)v1 ^ (unsigned __int8)byte_4212C0[v1]) != byte_41EA08[v1] )
      goto LABEL_6;
    ++v1;
  }
  while ( v1 < 0x1B );
  printf((int)"Right!\n");
~~~

((unsigned int8)v1 ^ (unsigned int8)byte_4212C0[v1]) != byte_41EA08[v1]

byte_41EA08是

~~~
.rdata:0041EA08 byte_41EA08     db 'M'                  
.rdata:0041EA09 aSawbFxzJTqjNBp db 'SAWB~FXZ:J:`tQJ"N@ bpdd}8g',0
~~~

~~~python
s="MSAWB~FXZ:J:`tQJ\"N@ bpdd}8g"
flag=""
for i in range(27):
    flag+=chr(ord(s[i])^i)
print flag

~~~



### findKey

全p一下，flag字符串位置

~~~c
void __usercall __noreturn sub_401A37(int a1@<ebp>)
{
  SetWindowTextA(*(HWND *)(a1 + 8), "flag{}");
  MessageBoxA(*(HWND *)(a1 + 8), "Are you kidding me?", "^_^", 0);
  ExitProcess(0);
}
~~~

看一下sub_401A37的调用，。。。无。有点问题。

看了wp才知道问题所在，两个push，nop一个，p一下。

~~~c
.text:00401918                 push    offset byte_428C54
.text:0040191D
.text:0040191D loc_40191D:                             ; CODE XREF: .text:0040193D↓j
.text:0040191D                 push    offset byte_428C54
~~~

+   1

~~~
strcpy(&v21, "0kk`d1a`55k222k2a776jbfgd`06cjjb");
strcpy(v17, "SS");
sub_401005(v17, (int)&v21, v9);
~~~

~~~c
//sub_401005--异或
unsigned int __cdecl sub_401590(LPCSTR lpString, int a2, int a3)
{
  unsigned int result; // eax
  unsigned int i; // [esp+4Ch] [ebp-Ch]
  unsigned int v5; // [esp+54h] [ebp-4h]

  v5 = lstrlenA(lpString);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a3 )
      break;
    *(_BYTE *)(i + a2) ^= lpString[i % v5];
  }
  return result;
}
~~~

~~~python
v21="0kk`d1a`55k222k2a776jbfgd`06cjjb"
r=""
for i in v21:
    r += chr(ord(i)^ord('S'))
print r
#c8837b23ff8aaa8a2dde915473ce0991
~~~

+   2

~~~
_strcmpi((const char *)&String1, &v21)
~~~

v21是c8837b23ff8aaa8a2dde915473ce0991，找string1是什么

发现string1结构CryptCreateHash。在附件找到0x8003u是md5

~~~c
CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash)
~~~

解密123321

+   3

最后有一个

~~~c
memcpy(&v16, &unk_423030, 0x32u);
v10 = strlen(&v16);
sub_401005(&v25, (int)&v16, v10);
~~~

v25是string1未加密的，就是123321

~~~python
a=[0x57 ,0x5E ,0x52 ,0x54,0x49 ,0x5F,1,0x6D ,0x69,0x46 ,2,0x6E,0x5F,2,0x6C ,0x57 ,0x5B,0x54 ,0x4C]
b="123321"
flag=""
for i in range(len(a)):
    flag+=chr(ord(b[i%6])^a[i])
print flag

~~~

## day30 6.9

打了学校的awd，专注拿flag，没有搅屎，以至于后期flag少了很多。还是没什么经验。

### [WUSTCTF2020]level3

看字符串是变换的base64

这是加密后的flag

~~~
d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD==
~~~

进入base64_encode查看

base64_table是正常的

emmm，再找找。肯定对base64_table做了变换，x一下找到

~~~c
__int64 O_OLookAtYou()
{
  char v0; // ST03_1
  __int64 result; // rax
  signed int i; // [rsp+2h] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    v0 = base64_table[i];
    base64_table[i] = base64_table[19 - i];
    result = 19 - i;
    base64_table[result] = v0;
  }
  return result;
}
~~~

换位置。

~~~c
#include <stdio.h>
#include <iostream>
using namespace std;
int main()
{
    char base64_table[100]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char v0; // ST03_1
    int result; // rax
    signed int i; // [rsp+2h] [rbp-4h]

    for ( i = 0; i <= 9; ++i )
    {
        v0 = base64_table[i];
        base64_table[i] = base64_table[19 - i];
        result = 19 - i;
        base64_table[result] = v0;
    }
    cout<<base64_table<<endl;
    return result;
}
//TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
~~~

~~~python
import base64
eflag="d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD=="
be64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
base64="TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
flag=''
for i in eflag:
    if i =="=":
        flag+="="
    else:
        flag+=be64[base64.find(i)]
print flag
print base64.b64decode(flag)
#d2N0ZjIwMjB7QmFzZTY0X2lzX3RoZV9zdGFydF9vZl9yZXZlcnNlfQ==
~~~

不知道为什么python报错'str' object has no attribute 'b64decode'

## day31 6.23

放假了，emm。好久没刷题了

### [MRCTF2020]hello_world_go

打开看就很奇怪，字符串一堆让人眼花缭乱。

其中runtime_staticbytes是包含ascii表，看引用runtime_intstring。emm

看main函数里unk_4D3C58找到flag

## day32 7.1

### [FlareOn5]Minesweeper Championship Registration

扫雷锦标赛注册，emm

>   Welcome to the Fifth Annual Flare-On Challenge! The Minesweeper World Championship is coming soon and we found the registration app. You weren't *officially* invited but if you can figure out what the code is you can probably get in anyway. Good luck!
>
>   Hint:本题解出相应字符串后请用flag{}包裹，形如：flag{123456@flare-on.com}

java的逆向，百度一下下一个jd-gui，官网打不开，去github



### [网鼎杯 2020 青龙组]singal

无壳32位，输入字符串

`read`函数限定15位

~~~c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+18h] [ebp-1D4h]

  __main();
  qmemcpy(&v4, &unk_403040, 0x1C8u);
  vm_operad(&v4, 114);
  puts("good,The answer format is:flag {}");
  return 0;
}
~~~

主要就是`vm_operad`

~~~c
int __cdecl vm_operad(int *a1, int a2)
{
  int result; // eax
  char v3[100]; // [esp+13h] [ebp-E5h]
  char v4[100]; // [esp+77h] [ebp-81h]
  char v5; // [esp+DBh] [ebp-1Dh]
  int v6; // [esp+DCh] [ebp-1Ch]
  int v7; // [esp+E0h] [ebp-18h]
  int v8; // [esp+E4h] [ebp-14h]
  int v9; // [esp+E8h] [ebp-10h]
  int v10; // [esp+ECh] [ebp-Ch]

  v10 = 0;
  v9 = 0;
  v8 = 0;
  v7 = 0;
  v6 = 0;
  while ( 1 )
  {
    result = v10;
    if ( v10 >= a2 )
      return result;
    switch ( a1[v10] )                          // v10 是a1坐标
    {
      case 1:
        v4[v7] = v5;                            // v7 是v4坐标
        ++v10;
        ++v7;
        ++v9;
        break;                                  // v9 是v3坐标，v3是输入
      case 2:
        v5 = a1[v10 + 1] + v3[v9];
        v10 += 2;
        break;
      case 3:
        v5 = v3[v9] - LOBYTE(a1[v10 + 1]);
        v10 += 2;
        break;
      case 4:
        v5 = a1[v10 + 1] ^ v3[v9];
        v10 += 2;
        break;
      case 5:
        v5 = a1[v10 + 1] * v3[v9];
        v10 += 2;
        break;
      case 6:
        ++v10;
        break;
      case 7:
        if ( v4[v8] != a1[v10 + 1] )
        {
          printf("what a shame...");
          exit(0);
        }
        ++v8;
        v10 += 2;
        break;
      case 8:
        v3[v6] = v5;
        ++v10;
        ++v6;
        break;
      case 10:
        read(v3);
        ++v10;
        break;
      case 11:
        v5 = v3[v9] - 1;
        ++v10;
        break;
      case 12:
        v5 = v3[v9] + 1;
        ++v10;
        break;
      default:
        continue;
    }
  }
}
~~~

`unk_403040`第一个数就是10，执行了`read`

我淦，我的保存呢，只有未完成的了

~~~python

from z3 import*
n=0
def tf(flag):
	global n
	if flag==0:
		return 'rflag['+str(n)+']'
	else:
		return ''
a='''
0A 00 00 00 04 00 00 00  10 00 00 00 08 00 00 00
03 00 00 00 05 00 00 00  01 00 00 00 04 00 00 00
20 00 00 00 08 00 00 00  05 00 00 00 03 00 00 00
01 00 00 00 03 00 00 00  02 00 00 00 08 00 00 00
0B 00 00 00 01 00 00 00  0C 00 00 00 08 00 00 00
04 00 00 00 04 00 00 00  01 00 00 00 05 00 00 00
03 00 00 00 08 00 00 00  03 00 00 00 21 00 00 00
01 00 00 00 0B 00 00 00  08 00 00 00 0B 00 00 00
01 00 00 00 04 00 00 00  09 00 00 00 08 00 00 00
03 00 00 00 20 00 00 00  01 00 00 00 02 00 00 00
51 00 00 00 08 00 00 00  04 00 00 00 24 00 00 00
01 00 00 00 0C 00 00 00  08 00 00 00 0B 00 00 00
01 00 00 00 05 00 00 00  02 00 00 00 08 00 00 00
02 00 00 00 25 00 00 00  01 00 00 00 02 00 00 00
36 00 00 00 08 00 00 00  04 00 00 00 41 00 00 00
01 00 00 00 02 00 00 00  20 00 00 00 08 00 00 00
05 00 00 00 01 00 00 00  01 00 00 00 05 00 00 00
03 00 00 00 08 00 00 00  02 00 00 00 25 00 00 00
01 00 00 00 04 00 00 00  09 00 00 00 08 00 00 00
03 00 00 00 20 00 00 00  01 00 00 00 02 00 00 00
41 00 00 00 08 00 00 00  0C 00 00 00 01 00 00 00
07 00 00 00 22 00 00 00  07 00 00 00 3F 00 00 00
07 00 00 00 34 00 00 00  07 00 00 00 32 00 00 00
07 00 00 00 72 00 00 00  07 00 00 00 33 00 00 00
07 00 00 00 18 00 00 00  07 00 00 00 A7 FF FF FF
07 00 00 00 31 00 00 00  07 00 00 00 F1 FF FF FF
07 00 00 00 28 00 00 00  07 00 00 00 84 FF FF FF
07 00 00 00 C1 FF FF FF  07 00 00 00 1E 00 00 00
07 00 00 00 7A 00 00 00  00 00 00 00 00 00 00 00
'''

listcz= a.replace('00','').replace('\n',' ').split()
print listcz
enflag=[]
for i in range(len(listcz)):
	if listcz[i]=='07':
		enflag.append(listcz[i+1])
print enflag
print len(enflag)
print tf(0)

cz=['04', '10', '08', '03', '05', '01', '04', '20', '08', '05', '03', '01', '03', '02', '08', '0B', '01', '0C', '08', '04', '04', '01', '05', '03', '08', '03', '21', '01', '0B', '08', '0B', '01', '04', '09', '08', '03', '20', '01', '02', '51', '08', '04', '24', '01', '0C', '08', '0B', '01', '05', '02', '08', '02', '25', '01', '02', '36', '08', '04', '41', '01', '02', '20', '08', '05', '01', '01', '05', '03', '08', '02', '25', '01', '04', '09', '08', '03', '20', '01', '02', '41', '08', '0C', '01']
rflag = [0]*15
'''
for i in range(15):
    rflag[i] = BitVec('rflag['+str(i)+']',64)
s=Solver() 
'''
str1='s.add('
i=0
print len(cz)
flag=0

while i==0:

	print i
	if cz[i]=='04':
		str1+=tf(flag)+'^'+'0x'+cz[i+1]
		flag=1
		i+=2
	elif cz[i]=='02':
		str1+=tf(flag)+'+'+'0x'+cz[i+1]
		flag=1
		i+=2
	elif cz[i]=='03':
		str1+=tf(flag)+'+'+'0x'+cz[i+1]
		flag=1
		i+=2
	elif cz[i]=='05':
		str1+=tf(flag)+'*'+'0x'+cz[i+1]
		flag=1
		i+=2
	elif cz[i]=='0c':
		str1+=tf(flag)+'+'+cz[i+1]
		flag=1
		i+=2
	elif cz[i]=='0B':
		str1+=tf(flag)+'-'+cz[i+1]
		flag=1
		i+=2
	elif cz[i]=='08':
		i+=1
	elif cz[i]=='01':
		print n
		str1+=')'
		print str1 
		#eval(str)
		n+=1
		flag=0
		str1=str1[:6]

~~~



[angr](https://yq.aliyun.com/articles/230560?spm=5176.10695662.1996646101.searchclickresult.196e62ebqoa0dS)

https://blog.csdn.net/Breeze_CAT/article/details/106139253

~~~python
import angr

p = angr.Project('./signal.exe')   #指定angr跑的程序
state = p.factory.entry_state()    #新建一个SimState的对象，得到一个初始化到二进制入口函数的SimState对象。
simgr = p.factory.simgr(state)   #创建simulation manager，angr的主要入口

simgr.explore(find=0x004017A5 ,avoid=0x004016E6)  #争取跑到输出成功的地址，避免跑到输出wrong的地址
flag = simgr.found[0].posix.dumps(0)[:15]     #得到flag
print(flag)

~~~



## day33 7.2

### [MRCTF2020]PixelShooter

像素射手

安卓逆向

| 内容入口            | 含义解释                                                     |
| ------------------- | ------------------------------------------------------------ |
| AndroidManifest.xml | 二进制xml文件，提供设备运行应用程序所需的各种信息            |
| classes.dex         | 以dex格式编译的应用程序代码                                  |
| resources.arsc      | 包含预编译应用程序资源的二进制XML文件                        |
| res/                | 此文件夹中包含未编译到resources.arsc文件中的资源             |
| assets/             | 此文件夹包含应用程序的原始资源，由AssetManager提供对这些资产文件的访问 |
| META-INF/           | 它包含MANIFEST.MF文件，该文件存储有关JAR内容的元数据。APK签名也存储在此文件夹中 |
| lib/                | 此文件夹包含已编译的代码，例如本地代码库                     |

进去打飞机。

unity召唤dnspy，找到Assembly-CSharp，gameover

### [RoarCTF2019]polyre

~~~shell
[root@lalala re]# ./attachment
Input:flag
Wrong!
~~~

ida里看一下，wdf

看wp知道是控制流平坦化，angr环境配半天，docker国内镜像没有，慢的一p

## day34 7.3

### [GKCTF2020]Chelly's identity

~~~
hi.Are you know of chelly?
Can you speak chelly's identity?
if you can, I will give you flag.
Give your answer:
my wife
bad long!
请按任意键继续. . .
~~~

题目错了

flag是16位，可以通过ida看出来或手动试试

+   对输入(v43)动手脚

~~~
  for ( i = 0; ; ++i )
  {
    v17 = sub_631771(&v43);
    if ( v17 == sub_6311D6(&v42) )
      break;
    v40 = *(char *)sub_631528(i);
    sub_6315D2(&v40);
  }
~~~

`sub_631771` 和 `sub_6311D6` 最后都调用了 `sub_6314DD`

先看判断`sub_411852`

`sub_4112F8`应该是开辟空间的

## day35 7.8

### challenge1

~~~~c
v6 = "x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q";
  WriteFile(hFile, "Enter password:\r\n", 0x12u, &NumberOfBytesWritten, 0);
  ReadFile(v7, &Buffer, 0x80u, &NumberOfBytesWritten, 0);
  v5 = sub_401260((int)&Buffer, NumberOfBytesWritten - 2);
  if ( !strcmp(v5, v6) )
    WriteFile(hFile, "Correct!\r\n", 0xBu, &NumberOfBytesWritten, 0);
  else
    WriteFile(hFile, "Wrong password\r\n", 0x11u, &NumberOfBytesWritten, 0);
~~~~

`sub_401260`很明显是一个base64，换表

~~~python
import base64
eflag="x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q"
be64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
base64="ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/"
flag=""
for i in eflag:
    if i =="=":
        flag+="="
    else:
        flag+=be64[base64.find(i)]
print flag
flag= base64.b64decode(flag)
print flag
~~~



### [Zer0pts2020]easy strcmp

main函数很简单，就是输入strcmp zer0pts{\*\*\*\*\*\*\**CENSORED\*\*\*\*\*\*\*\*}

找到对输入操作的函数

~~~c
__int64 __fastcall sub_6EA(__int64 a1, __int64 a2)
{
  int i; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    ;
  v4 = (i >> 3) + 1;
  for ( j = 0; j < v4; ++j )
    *(_QWORD *)(8 * j + a1) -= qword_201060[j];
  return qword_201090(a1, a2);
}
~~~

~~~
qword_201060    dq 0, 410A4335494A0942h, 0B0EF2F50BE619F0h, 4F0A3A064A35282Bh
~~~

第一个for循环获得输入位数，第二个for循环将输入分为8位一组减去一个数，所以zer0pts{-0还是zer0pts{。

写脚本

~~~python
import binascii
enflag="********CENSORED********"
num=[0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B]
print len(enflag)

flag=''
for i in range(3):
	print i
	print enflag[8*i:8*i+8][::-1]
	t = binascii.b2a_hex(enflag[8*i:8*i+8][::-1])
	a=hex(num[i]+int(t,16))
	flag+= binascii.a2b_hex(str(a).replace('0x','').replace('L',''))[::-1]
	
print flag
~~~

一开始没有考虑大小端问题，中间CENSORED出错了。

## day36 7.13

### [安洵杯 2019]game

控制流平坦化，恶心

### [ACTF新生赛2020]Universe_final_answer

判断语句

~~~c
  if ( sub_860(&v5) )
  {
    sub_C50(&v5, &v4);
    __printf_chk(1LL, "Judgement pass! flag is actf{%s_%s}\n", &v5);
  }
~~~

函数`sub_860`一大堆判断

~~~c
  if ( -85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613 )
  {
    v11 = a1[9];
    if ( 30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400
      && -103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283
      && 71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855
      && 5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944
      && -54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222
      && -83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258
      && 81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559
      && 101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308 )
    {
      result = 99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697;
    }
  }
~~~

z3求一下

~~~python
#!/usr/bin/python
# -*- coding: utf-8 -*-
from z3 import *

#申明未知量
v1 = BitVec('v1',10)
v2 = BitVec('v2',10)
v3 = BitVec('v3',10)
v4 = BitVec('v4',10)
v5 = BitVec('v5',10)
v6 = BitVec('v6',10)
v7 = BitVec('v7',10)
v8 = BitVec('v8',10)
v9 = BitVec('v9',10)
v11 = BitVec('v11',10)
s=Solver() # 创建约束求解器

# 添加约束条件
s.add( -85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613 )
s.add( 30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400 )
s.add( -103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283 )
s.add( 71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855 )
s.add( 5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944 )
s.add( -54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222 )
s.add( -83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258 )
s.add( 81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559 )
s.add( 101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308 )
s.add( 99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697 )

# 检查是否有解

print s.check()

m=s.model()
for d in m.decls():   # decls()返回model包含了所有符号的列表
    print("%s = %s" % (d.name(),m[d]))
~~~

注意位置，这是一半：F0uRT_y7w@

淦，里面还有6、7位置

第二部分就是9异或字符串

再将数字变为字符串

~~~python
f1='F0uRTy_7w@'
f2=9
for i in f1:
	f2^=ord(i)
print f1+'_'+str(f2)
~~~

## day37 7.31

### [ACTF新生赛2020]Oruga

tell me the flag

~~~c
  printf("Tell me the flag:", 0LL);
  scanf("%s", s);
  strcpy(s2, "actf{");
  LODWORD(v4) = 0;
  while ( (signed int)v4 <= 4 )
  {
    *((_BYTE *)&v4 + (signed int)v4 + 4) = s[(signed int)v4];
    LODWORD(v4) = v4 + 1;
  }
  v8 = 0;
  if ( !strcmp((const char *)&v4 + 4, s2) )
  {
    if ( (unsigned __int8)sub_78A(s, s2) )
      printf("That's True Flag!", v6);
    else
      printf("don't stop trying...", v7);
    result = 0LL;
  }
  else
  {
    printf("Format false!", s2, v5);
    result = 0LL;
  }
~~~

其中`if ( !strcmp((const char *)&v4 + 4, s2) )`就是判断flag格式是否为``actf{``，然后进入`sub_78A` 。

看到

~~~
if ( *(_BYTE *)(v3 + a1) != 'W' || v4 == -16 )
    {
      if ( *(_BYTE *)(v3 + a1) != 'E' || v4 == 1 )
      {
        if ( *(_BYTE *)(v3 + a1) != 'M' || v4 == 16 )
        {
          if ( *(_BYTE *)(v3 + a1) != 'J' || v4 == -1 )
            return 0LL;
          v4 = -1;
        }
        else
        {
          v4 = 16;
        }
      }
      else
      {
        v4 = 1;
      }
    }
    else
    {
      v4 = -16;
    }
~~~

这样子就感觉是个迷宫，W上，E右，M下，J左。把byte_201020数据提取，一行16个。奇怪的是一组判断

~~~c
	while ( !byte_201020[v2] )
    {
      if ( v4 == -1 && !(v2 & 0xF) )
        return 0LL;
      if ( v4 == 1 && v2 % 16 == 15 )
        return 0LL;
      if ( v4 == 16 && (unsigned int)(v2 - 240) <= 15 )
        return 0LL;
      if ( v4 == -16 && (unsigned int)(v2 + 15) <= 30 )
        return 0LL;
      v2 += v4;
    }
~~~

前4个if应该是判断出界，后面v2+=v4就是当byte_201020[v2]==0时可以继续走。

走到21h结束

~~~

    00 00 00 00 23 00 00 00 00 00 00 00 23 23 23 23
    00 00 00 23 23 00 00 00 4F 4F 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 4F 4F 00 50 50 00 00 00
    00 00 00 4C 00 4F 4F 00 4F 4F 00 50 50 00 00 00
    00 00 00 4C 00 4F 4F 00 4F 4F 00 50 00 00 00 00
    00 00 4C 4C 00 4F 4F 00 00 00 00 50 00 00 00 00
    00 00 00 00 00 4F 4F 00 00 00 00 50 00 00 00 00
    23 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 23 00 00 00
    00 00 00 00 00 00 4D 4D 4D 00 00 00 23 00 00 00
    00 00 00 00 00 00 00 4D 4D 4D 00 00 00 00 45 45
    00 00 00 30 00 4D 00 4D 00 4D 00 00 00 00 45 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 45 45
    54 54 54 49 00 4D 00 4D 00 4D 00 00 00 00 45 00
    00 54 00 49 00 4D 00 4D 00 4D 00 00 00 00 45 00
    00 54 00 49 00 4D 00 4D 00 4D 21 00 00 00 45 45

~~~

flag{MEWEMEWJMEWJM}

## day38 8.1

### [FlareOn5]Ultimate Minesweeper

>   You hacked your way into the Minesweeper Championship, good job. Now its time to compete. Here is the Ultimate Minesweeper binary. Beat it, win the championship, and we'll move you on to greater challenges.
>
>   Hint:本题解出相应字符串后请用flag{}包裹，形如：flag{123456@flare-on.com}

900个格子，897个雷，好玩。这是net程序，用dnspy打开，这个题目应该是让我们去修改雷个数或什么东西。

`getkey`里有个数组很像flag

~~~c#
private string GetKey(List<uint> revealedCells)
		{
			revealedCells.Sort();
			Random random = new Random(Convert.ToInt32(revealedCells[0] << 20 | revealedCells[1] << 10 | revealedCells[2]));
			byte[] array = new byte[32];
			byte[] array2 = new byte[]
			{
				245,
				75,
				65,
				142,
				68,
				71,
				100,
				185,
				74,
				127,
				62,
				130,
				231,
				129,
				254,
				243,
				28,
				58,
				103,
				179,
				60,
				91,
				195,
				215,
				102,
				145,
				154,
				27,
				57,
				231,
				241,
				86
			};
			random.NextBytes(array);
			uint num = 0U;
			while ((ulong)num < (ulong)((long)array2.Length))
			{
				byte[] array3 = array2;
				uint num2 = num;
				array3[(int)num2] = (array3[(int)num2] ^ array[(int)num]);
				num += 1U;
			}
			return Encoding.ASCII.GetString(array2);
		}
~~~

但`random.NextBytes(array);`有随机数，放弃。

`AllocateMemory`是生成雷区

~~~c#
private void AllocateMemory(MineField mf)
		{
			for (uint num = 0U; num < MainForm.VALLOC_NODE_LIMIT; num += 1U)
			{
				for (uint num2 = 0U; num2 < MainForm.VALLOC_NODE_LIMIT; num2 += 1U)
				{
					bool flag = true;
					uint r = num + 1U;
					uint c = num2 + 1U;
					if (this.VALLOC_TYPES.Contains(this.DeriveVallocType(r, c)))
					{
						flag = false;
					}
					mf.GarbageCollect[(int)num2, (int)num] = flag;
				}
			}
		}
~~~

将`if (this.VALLOC_TYPES.Contains(this.DeriveVallocType(r, c)))`改成`if ((r == 1U && c == 1U) || (r == 1U && c == 2U) || (r == 1U && c == 3U))`后安全区改为（1.1）（1.2）（1.3）但最后输出flag错误，这是因为`random.NextBytes(array);`随机数用到了安全坐标。

再看`getkey`的引用

~~~c#
private void SquareRevealedCallback(uint column, uint row)
{
	if (this.MineField.BombRevealed)
	{
		this.stopwatch.Stop();
		Application.DoEvents();
		Thread.Sleep(1000);
		new FailurePopup().ShowDialog();
		Application.Exit();
	}
	this.RevealedCells.Add(row * MainForm.VALLOC_NODE_LIMIT + column);
	if (this.MineField.TotalUnrevealedEmptySquares == 0)
	{
		this.stopwatch.Stop();
		Application.DoEvents();
		Thread.Sleep(1000);
		new SuccessPopup(this.GetKey(this.RevealedCells)).ShowDialog();
		Application.Exit();
	}
}
~~~

很明显两个判断，第一个是雷。先改程序，把第一个`Thread.Sleep(1000);new FailurePopup().ShowDialog();Application.Exit();`删了就可以找三个点。

但是这样还是很麻烦，需要一个一个点，根据[Harmonica_11](https://www.cnblogs.com/harmonica11/p/12917262.html)可以在AllocateMemory添加

~~~
Console.Write(r);
Console.Write(c);//断点下在这
~~~

### [安洵杯 2019]game

emm，再搞一次

主要函数

~~~c
while ( 1 )
  {
    while ( 1 )
    {
      while ( v7 == -2071121728 )
      {
        v4 = blank_num((int (*)[9])sudoku);
        v5 = (signed int *)mem_alloc(v4);
        trace((__int64)sudoku, v5, v4);
        check((int (*)[9])sudoku);
        check1(&v8);
        check3(&v8);
        v9 = 0;
        v7 = -303742386;
      }
      if ( v7 != -1804515313 )
        break;
      v3 = -2071121728;
      if ( v10 )
        v3 = 664169471;
      v7 = v3;
    }
    if ( v7 == -303742386 )
      break;
    if ( v7 == 664169471 )
    {
      printf("error");
      check((int (*)[9])sudoku);
      v9 = 0;
      v7 = -303742386;
    }
  }
~~~



进入`blank_num`，理清流程

~~~c
  v6 = 0;
  v8 = 0;
  v5 = 1046773218;
  while ( 1 )
  {
    while ( v5 == -1892951115 )
    {
      v7 = 0;
      v5 = -1048142948;
    }
    if ( v5 == -1585203536 )                    // 退出
      break;
    switch ( v5 )
    {
      case -1237447983:
        v5 = 1058605341;
        break;
      case -1048142948:
        v2 = -1237447983;                       // 2.
                                                // v7>9 ++v8 回到1
        if ( v7 < 9 )                           // v7<9 进入3
          v2 = 1501457574;
        v5 = v2;
        break;
      case -1026222996:
        ++v7;
        v5 = -1048142948;
        break;
      case -516195663:
        ++v6;
        v5 = 710936108;
        break;
      case 710936108:
        v5 = -1026222996;
        break;
      case 1046773218:                          // 1.
        v1 = -1585203536;                       // v8>9 退出
        if ( v8 < 9 )                           // v8<9 设v7=0，进入2
          v1 = -1892951115;
        v5 = v1;
        break;
      case 1058605341:
        ++v8;
        v5 = 1046773218;
        break;
      case 1501457574:                          // 3.
        v3 = 710936108;                         // sudoku[9*v8+v7]!=0 ++v7 回到2
        if ( !(*a1)[9 * v8 + v7] )              // sudoku[9*v8+v7] =0 ++v6 ++v7 回到2
          v3 = -516195663;
        v5 = v3;
        break;
    }
  }
  return v6;
~~~

其实到最后就是`if ( !(*a1)[9 * v8 + v7] )`然后返回了数独数组中0的个数，动调后发现返回值为40。



`trace((__int64)sudoku, v5, v4);` 和 `check((int (*)[9])sudoku);` 感觉没用，一来它们的返回值没有用，二没有改变sudoku，pass。（这个不清楚）

 `check1`

~~~c
while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                while ( v10 == -2084833488 )
                {
                  v8 = strlen(a1);
                  v9 = -67245798;
                  if ( v12 < v8 )               // v12<flag长度
                    v9 = 1974939745;
                  v10 = v9;
                }
                if ( v10 != -1988665894 )
                  break;
                v12 = 0;
                v10 = -2084833488;
              }
              if ( v10 != -1393133668 )
                break;
              v5 = strlen(a1);
              v6 = -1988665894;                 // v12>flag长度 v12=0 进入4
              if ( v12 < v5 )
                v6 = -1018472136;
              v10 = v6;
            }
            if ( v10 != -1018472136 )
              break;
            v7 = a1[v12];
            a1[v12] = a1[v12 + 1];
            a1[v12 + 1] = v7;
            v10 = -146751883;
          }
          if ( v10 != -831482631 )
            break;
          ++v12;
          v10 = -2084833488;
        }
        if ( v10 != -291294424 )
          break;
        ++v11;
        ++v12;
        v10 = 1519002972;
      }
      if ( v10 != -146751883 )
        break;
      v12 += 2;
      v10 = -1393133668;
    }
    result = (unsigned int)(v10 + 67245798);
    if ( v10 == -67245798 )
      break;
    switch ( v10 )
    {
      case 75381312:                            // 2.
        v4 = a1[v12];                           // flag[v11] [v12]互换 (前后部分)
        a1[v12] = a1[v11];
        a1[v11] = v4;
        v10 = -291294424;                       // ++v11 ++v12 回1
        break;
      case 1519002972:                          // 1.
        v2 = strlen(a1);                        // v2=flag长度
        v3 = 1555725255;                        // v11>flag长度一半 v12=0 进入3
        if ( v11 < v2 >> 1 )                    // v11<flag长度一半 进入2
          v3 = 75381312;
        v10 = v3;
        break;
      case 1555725255:                          // 3.
        v12 = 0;                                // flag[v12][v12+1]互换，v12+=2...... 当全部换完后进入4 v12=0
        v10 = -1393133668;
        break;
      case 1974939745:                          // 4.
        a1[v12] = (a1[v12] & 0xF3 | ~a1[v12] & 0xC) - 20;
        v10 = -831482631;
        break;
    }
  }
~~~

所以check1将flag先前后互换、两位互换，最后a1[v12] = (a1[v12] & 0xF3 | ~a1[v12] & 0xC) - 20;

`check3` 

没什么用，只有里面`check2`有用

~~~c
  s = a1;
  v13 = 0;
  v12 = 1;
  v15 = 0;
  v11 = -2671583;
  while ( 1 )                                   // 1.
  {
    while ( 1 )
    {
      while ( 1 )                               // 3.
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( 1 )                       // 4.
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
                          while ( 1 )
                          {
                            while ( 1 )
                            {
                              while ( 1 )
                              {
                                while ( v11 == -2119125118 )
                                {
                                  ++v15;
                                  v11 = -94879051;
                                }
                                if ( v11 != -1998111552 )
                                  break;
                                v6 = 396170963;
                                if ( v15 < 9 )
                                  v6 = -512482015;
                                v11 = v6;
                              }
                              if ( v11 != -1695072055 )
                                break;
                              ++v15;
                              v11 = -1998111552;
                            }
                            if ( v11 != -1658909923 )
                              break;
                            v8 = -1129833658;
                            if ( D0g3[9 * v15 + v14] != sudoku[9 * v15 + v14] )
                              v8 = -528396247;
                            v11 = v8;
                          }
                          if ( v11 != -1613667829 )
                            break;
                          v11 = -2119125118;
                        }
                        if ( v11 != -1369143226 )
                          break;
                        v14 = 0;
                        v11 = -740861019;
                      }
                      if ( v11 != -1244045086 )
                        break;
                      D0g3[9 * v15 + v14] = v16[v13++];
                      v11 = 1611237474;
                    }
                    if ( v11 != -1129833658 )
                      break;
                    v11 = -90011013;
                  }
                  if ( v11 != -740861019 )
                    break;                      // 4.
                  v4 = -1613667829;             // v14>9 ++v15 回3.
                  if ( v14 < 9 )                // v14<9 进入5
                    v4 = 705300330;
                  v11 = v4;
                }
                if ( v11 != -528396247 )
                  break;
                v12 = 0;
                v11 = 1954800504;
              }
              if ( v11 != -512482015 )
                break;
              v14 = 0;
              v11 = 564268595;
            }
            if ( v11 != -334121999 )
              break;
            v15 = 0;
            v11 = -1998111552;
          }
          if ( v11 != -94879051 )
            break;                              // 3.
          v3 = -334121999;
          if ( v15 < 9 )                        // v15<9 v14=0 进入4
            v3 = -1369143226;
          v11 = v3;
        }
        if ( v11 != -90011013 )
          break;
        ++v14;
        v11 = 564268595;
      }
      if ( v11 != -2671583 )
        break;                                  // 1.
      v1 = strlen(s);
      v2 = 2101131376;                          // v15>flag v15=0 打印回车 进入3.
      if ( v15 < v1 )                           // v15<flag 进入2.
        v2 = 441246003;
      v11 = v2;
    }
    if ( v11 == 396170963 )
      break;
    switch ( v11 )
    {
      case 430996436:
        ++v15;
        v11 = -2671583;
        break;
      case 441246003:                           // 2.
        v16[v15] = s[v15] - 232084296 + 232084248;// v16[v15]=s[v15]-48
        v11 = 430996436;                        // ++v15 回1.
        break;
      case 564268595:
        v7 = 1954800504;
        if ( v14 < 9 )
          v7 = -1658909923;
        v11 = v7;
        break;
      case 705300330:                           // 5.
        v5 = 1611237474;                        // D0g3[9 * v15 + v14]!=0 进入6
        if ( !D0g3[9 * v15 + v14] )             // D0g3[9 * v15 + v14]=0 D0g3[9 * v15 + v14] = v16[v13++]; 进入6
          v5 = -1244045086;
        v11 = v5;
        break;
      case 1611237474:                          // 6.
        v11 = 2119231421;                       // ++v14 回4
        break;
      case 1908623879:
        v11 = -1695072055;
        break;
      case 1954800504:
        v9 = 1908623879;
        if ( !v12 )
          v9 = 2014359934;
        v11 = v9;
        break;
      case 2014359934:
        v11 = 396170963;
        break;
      case 2101131376:
        v15 = 0;
        v11 = -94879051;
        printf("\n");
        break;
      case 2119231421:
        ++v14;
        v11 = -740861019;
        break;
    }
  }
~~~

流程：dog3=flag-48==sudoku

现在需要知道前后的sudoku，动调。不知道为什么dd变db了

[![a8I9KO.png](https://s1.ax1x.com/2020/08/01/a8I9KO.png)](https://imgchr.com/i/a8I9KO)

![a85vP1.png](https://s1.ax1x.com/2020/08/01/a85vP1.png)

~~~python
sudoku = [1, 4, 5, 3, 2, 7, 6, 9, 8, 8, 3, 9, 6, 5, 4, 1, 2, 7, 6, 7, 2, 8, 1, 9, 5, 4, 3, 4, 9, 6, 1, 8, 5, 3, 7, 2, 2, 1, 8, 4, 7, 3, 9, 5, 6, 7, 5, 3, 2, 9, 6, 4, 8, 1, 3, 6, 7, 5, 4, 2, 8, 1, 9, 9, 8, 4, 7, 6, 1, 2, 3, 5, 5, 2, 1, 9, 3, 8, 7, 6, 4]
dog3   = [1, 0, 5, 3, 2, 7, 0, 0, 8, 8, 0, 9, 0, 5, 0, 0, 2, 0, 0, 7, 0, 0, 1, 0, 5, 0, 3, 4, 9, 0, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0, 7, 0, 9, 0, 6, 7, 0, 3, 2, 9, 0, 4, 8, 0, 0, 6, 0, 5, 4, 0, 8, 0, 9, 0, 0, 4, 0, 0, 1, 0, 3, 0, 0, 2, 1, 0, 3, 0, 7, 0, 4]
flag = []
for i in range(81):
    if dog3[i] == 0:
        num = ord(str(sudoku[i])) + 20
        flag.append( num&0xf3 | ~num&0xc )

for i in range(0,40,2):
    (flag[i], flag[i+1]) = (flag[i+1], flag[i])
	
for i in range(20):
    (flag[i],flag[i+20]) = (flag[i+20], flag[i])
	
for i in range(40):
    print chr(flag[i]),
~~~





## 知识点

[NET](https://baike.baidu.com/item/NET)语言的全称应该是ASP.NET，是[微软](https://baike.baidu.com/item/微软/124767)新推出的一种[编程](https://baike.baidu.com/item/编程/139828)框架理论或者说是一种编程标准，它可以通过微软出品的Visual Studio 开发工具进行项目开发，应用于网站类的开发一般使用C#语言进行编写，应用程序类一般使用VB进行编写。

unity是用C#开发，被编译到了 Assembly-CSharp.dll

*C#*是微软公司发布的一种由C和C++衍生出来的面向对象的编程语言、运行于.NET Framework和.NET Core(完全开源，跨平台)之上的高级程序设计语言。

dnSpy 是一款针对 .NET 程序的逆向工程工具。

### lo、hiword

LOWORD()得到一个32bit数的低16bit  
HIWORD()得到一个32bit数的高16bit
LOBYTE()得到一个16bit数最低（最右边）那个字节
HIBYTE()得到一个16bit数最高（最左边）那个字节

### IDA逆向常用宏定义

~~~c
/*

   This file contains definitions used by the Hex-Rays decompiler output.
   It has type definitions and convenience macros to make the
   output more readable.

   Copyright (c) 2007-2011 Hex-Rays

*/

#if defined(__GNUC__)
  typedef          long long ll;
  typedef unsigned long long ull;
  #define __int64 long long
  #define __int32 int
  #define __int16 short
  #define __int8  char
  #define MAKELL(num) num ## LL
  #define FMT_64 "ll"
#elif defined(_MSC_VER)
  typedef          __int64 ll;
  typedef unsigned __int64 ull;
  #define MAKELL(num) num ## i64
  #define FMT_64 "I64"
#elif defined (__BORLANDC__)
  typedef          __int64 ll;
  typedef unsigned __int64 ull;
  #define MAKELL(num) num ## i64
  #define FMT_64 "L"
#else
  #error "unknown compiler"
#endif
typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned long ulong;

typedef          char   int8;
typedef   signed char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef   signed short  sint16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef   signed int    sint32;
typedef unsigned int    uint32;
typedef ll              int64;
typedef ll              sint64;
typedef ull             uint64;

// Partially defined types:
#define _BYTE  uint8
#define _WORD  uint16
#define _DWORD uint32
#define _QWORD uint64
#if !defined(_MSC_VER)
#define _LONGLONG __int128
#endif

#ifndef _WINDOWS_
typedef int8 BYTE;
typedef int16 WORD;
typedef int32 DWORD;
typedef int32 LONG;
#endif
typedef int64 QWORD;
#ifndef __cplusplus
typedef int bool;       // we want to use bool in our C programs
#endif

// Some convenience macros to make partial accesses nicer
// first unsigned macros:
#define LOBYTE(x)   (*((_BYTE*)&(x)))   // low byte
#define LOWORD(x)   (*((_WORD*)&(x)))   // low word
#define LODWORD(x)  (*((_DWORD*)&(x)))  // low dword
#define HIBYTE(x)   (*((_BYTE*)&(x)+1))
#define HIWORD(x)   (*((_WORD*)&(x)+1))
#define HIDWORD(x)  (*((_DWORD*)&(x)+1))
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define WORDn(x, n)   (*((_WORD*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x)   BYTEn(x,  4)
#define BYTE5(x)   BYTEn(x,  5)
#define BYTE6(x)   BYTEn(x,  6)
#define BYTE7(x)   BYTEn(x,  7)
#define BYTE8(x)   BYTEn(x,  8)
#define BYTE9(x)   BYTEn(x,  9)
#define BYTE10(x)  BYTEn(x, 10)
#define BYTE11(x)  BYTEn(x, 11)
#define BYTE12(x)  BYTEn(x, 12)
#define BYTE13(x)  BYTEn(x, 13)
#define BYTE14(x)  BYTEn(x, 14)
#define BYTE15(x)  BYTEn(x, 15)
#define WORD1(x)   WORDn(x,  1)
#define WORD2(x)   WORDn(x,  2)         // third word of the object, unsigned
#define WORD3(x)   WORDn(x,  3)
#define WORD4(x)   WORDn(x,  4)
#define WORD5(x)   WORDn(x,  5)
#define WORD6(x)   WORDn(x,  6)
#define WORD7(x)   WORDn(x,  7)

// now signed macros (the same but with sign extension)
#define SLOBYTE(x)   (*((int8*)&(x)))
#define SLOWORD(x)   (*((int16*)&(x)))
#define SLODWORD(x)  (*((int32*)&(x)))
#define SHIBYTE(x)   (*((int8*)&(x)+1))
#define SHIWORD(x)   (*((int16*)&(x)+1))
#define SHIDWORD(x)  (*((int32*)&(x)+1))
#define SBYTEn(x, n)   (*((int8*)&(x)+n))
#define SWORDn(x, n)   (*((int16*)&(x)+n))
#define SBYTE1(x)   SBYTEn(x,  1)
#define SBYTE2(x)   SBYTEn(x,  2)
#define SBYTE3(x)   SBYTEn(x,  3)
#define SBYTE4(x)   SBYTEn(x,  4)
#define SBYTE5(x)   SBYTEn(x,  5)
#define SBYTE6(x)   SBYTEn(x,  6)
#define SBYTE7(x)   SBYTEn(x,  7)
#define SBYTE8(x)   SBYTEn(x,  8)
#define SBYTE9(x)   SBYTEn(x,  9)
#define SBYTE10(x)  SBYTEn(x, 10)
#define SBYTE11(x)  SBYTEn(x, 11)
#define SBYTE12(x)  SBYTEn(x, 12)
#define SBYTE13(x)  SBYTEn(x, 13)
#define SBYTE14(x)  SBYTEn(x, 14)
#define SBYTE15(x)  SBYTEn(x, 15)
#define SWORD1(x)   SWORDn(x,  1)
#define SWORD2(x)   SWORDn(x,  2)
#define SWORD3(x)   SWORDn(x,  3)
#define SWORD4(x)   SWORDn(x,  4)
#define SWORD5(x)   SWORDn(x,  5)
#define SWORD6(x)   SWORDn(x,  6)
#define SWORD7(x)   SWORDn(x,  7)


// Helper functions to represent some assembly instructions.

#ifdef __cplusplus

// Fill memory block with an integer value
inline void memset32(void *ptr, uint32 value, int count)
{
  uint32 *p = (uint32 *)ptr;
  for ( int i=0; i < count; i++ )
    *p++ = value;
}

// Generate a reference to pair of operands
template<class T>  int16 __PAIR__( int8  high, T low) { return ((( int16)high) << sizeof(high)*8) | uint8(low); }
template<class T>  int32 __PAIR__( int16 high, T low) { return ((( int32)high) << sizeof(high)*8) | uint16(low); }
template<class T>  int64 __PAIR__( int32 high, T low) { return ((( int64)high) << sizeof(high)*8) | uint32(low); }
template<class T> uint16 __PAIR__(uint8  high, T low) { return (((uint16)high) << sizeof(high)*8) | uint8(low); }
template<class T> uint32 __PAIR__(uint16 high, T low) { return (((uint32)high) << sizeof(high)*8) | uint16(low); }
template<class T> uint64 __PAIR__(uint32 high, T low) { return (((uint64)high) << sizeof(high)*8) | uint32(low); }

// rotate left
template<class T> T __ROL__(T value, uint count)
{
  const uint nbits = sizeof(T) * 8;
  count %= nbits;

  T high = value >> (nbits - count);
  value <<= count;
  value |= high;
  return value;
}

// rotate right
template<class T> T __ROR__(T value, uint count)
{
  const uint nbits = sizeof(T) * 8;
  count %= nbits;

  T low = value << (nbits - count);
  value >>= count;
  value |= low;
  return value;
}

// carry flag of left shift
template<class T> int8 __MKCSHL__(T value, uint count)
{
  const uint nbits = sizeof(T) * 8;
  count %= nbits;

  return (value >> (nbits-count)) & 1;
}

// carry flag of right shift
template<class T> int8 __MKCSHR__(T value, uint count)
{
  return (value >> (count-1)) & 1;
}

// sign flag
template<class T> int8 __SETS__(T x)
{
  if ( sizeof(T) == 1 )
    return int8(x) < 0;
  if ( sizeof(T) == 2 )
    return int16(x) < 0;
  if ( sizeof(T) == 4 )
    return int32(x) < 0;
  return int64(x) < 0;
}

// overflow flag of subtraction (x-y)
template<class T, class U> int8 __OFSUB__(T x, U y)
{
  if ( sizeof(T) < sizeof(U) )
  {
    U x2 = x;
    int8 sx = __SETS__(x2);
    return (sx ^ __SETS__(y)) & (sx ^ __SETS__(x2-y));
  }
  else
  {
    T y2 = y;
    int8 sx = __SETS__(x);
    return (sx ^ __SETS__(y2)) & (sx ^ __SETS__(x-y2));
  }
}

// overflow flag of addition (x+y)
template<class T, class U> int8 __OFADD__(T x, U y)
{
  if ( sizeof(T) < sizeof(U) )
  {
    U x2 = x;
    int8 sx = __SETS__(x2);
    return ((1 ^ sx) ^ __SETS__(y)) & (sx ^ __SETS__(x2+y));
  }
  else
  {
    T y2 = y;
    int8 sx = __SETS__(x);
    return ((1 ^ sx) ^ __SETS__(y2)) & (sx ^ __SETS__(x+y2));
  }
}

// carry flag of subtraction (x-y)
template<class T, class U> int8 __CFSUB__(T x, U y)
{
  int size = sizeof(T) > sizeof(U) ? sizeof(T) : sizeof(U);
  if ( size == 1 )
    return uint8(x) < uint8(y);
  if ( size == 2 )
    return uint16(x) < uint16(y);
  if ( size == 4 )
    return uint32(x) < uint32(y);
  return uint64(x) < uint64(y);
}

// carry flag of addition (x+y)
template<class T, class U> int8 __CFADD__(T x, U y)
{
  int size = sizeof(T) > sizeof(U) ? sizeof(T) : sizeof(U);
  if ( size == 1 )
    return uint8(x) > uint8(x+y);
  if ( size == 2 )
    return uint16(x) > uint16(x+y);
  if ( size == 4 )
    return uint32(x) > uint32(x+y);
  return uint64(x) > uint64(x+y);
}

#else
// The following definition is not quite correct because it always returns
// uint64. The above C++ functions are good, though.
#define __PAIR__(high, low) (((uint64)(high)<<sizeof(high)*8) | low)
// For C, we just provide macros, they are not quite correct.
#define __ROL__(x, y) __rotl__(x, y)      // Rotate left
#define __ROR__(x, y) __rotr__(x, y)      // Rotate right
#define __CFSHL__(x, y) invalid_operation // Generate carry flag for (x<<y)
#define __CFSHR__(x, y) invalid_operation // Generate carry flag for (x>>y)
#define __CFADD__(x, y) invalid_operation // Generate carry flag for (x+y)
#define __CFSUB__(x, y) invalid_operation // Generate carry flag for (x-y)
#define __OFADD__(x, y) invalid_operation // Generate overflow flag for (x+y)
#define __OFSUB__(x, y) invalid_operation // Generate overflow flag for (x-y)
#endif

// No definition for rcl/rcr because the carry flag is unknown
#define __RCL__(x, y)    invalid_operation // Rotate left thru carry
#define __RCR__(x, y)    invalid_operation // Rotate right thru carry
#define __MKCRCL__(x, y) invalid_operation // Generate carry flag for a RCL
#define __MKCRCR__(x, y) invalid_operation // Generate carry flag for a RCR
#define __SETP__(x, y)   invalid_operation // Generate parity flag for (x-y)

// In the decompilation listing there are some objects declarared as _UNKNOWN
// because we could not determine their types. Since the C compiler does not
// accept void item declarations, we replace them by anything of our choice,
// for example a char:

#define _UNKNOWN char

#ifdef _MSC_VER
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#endif
~~~

### Tea/XTea/XXTea

#### Tea

在[密码学](https://zh.wikipedia.org/wiki/密码学)中，**微型加密算法**（Tiny Encryption Algorithm，TEA）是一种易于描述和[执行](https://zh.wikipedia.org/w/index.php?title=执行&action=edit&redlink=1)的[块密码](https://zh.wikipedia.org/wiki/塊密碼)，通常只需要很少的代码就可实现。其设计者是[剑桥大学计算机实验室](https://zh.wikipedia.org/wiki/剑桥大学)的[大卫 · 惠勒](https://zh.wikipedia.org/w/index.php?title=大卫·惠勒&action=edit&redlink=1)与[罗杰 · 尼达姆](https://zh.wikipedia.org/w/index.php?title=罗杰·尼达姆&action=edit&redlink=1)。

参考代码：

```c
#include <stdint.h>

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
int main()
{
    uint32_t v[2]={1,2},k[4]={2,2,3,4};
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    encrypt(v, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    decrypt(v, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
    return 0;
}

```

#### XTea

XTEA是TEA的升级版，增加了更多的密钥表，移位和异或操作等等，设计者是Roger Needham, David Wheeler

~~~c
#include <stdio.h>
#include <stdint.h>
 
/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */
 
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}
 
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
 
int main()
{
    uint32_t v[2]={1,2};
    uint32_t const k[4]={2,2,3,4};
    unsigned int r=32;//num_rounds建议取值为32
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    encipher(r, v, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    decipher(r, v, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
    return 0;
}

~~~

#### XXTea

XXTEA，又称Corrected Block TEA，是XTEA的升级版，设计者是Roger Needham, David Wheeler

~~~c

#include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
 
void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52/n;
        sum = 0;
        z = v[n-1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p=0; p<n-1; p++)
            {
                y = v[p+1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n-1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52/n;
        sum = rounds*DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--)
            {
                z = v[p-1];
                y = v[p] -= MX;
            }
            z = v[n-1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}
 
 
int main()
{
    uint32_t v[2]= {1,2};
    uint32_t const k[4]= {2,2,3,4};
    int n= 2; //n的绝对值表示v的长度，取正表示加密，取负表示解密
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    btea(v, n, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    btea(v, -n, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
    return 0;
}
~~~

~~~python
############################################################  
#                                                          #  
# The implementation of PHPRPC Protocol 3.0                #  
#                                                          #  
# xxtea.py                                                 #  
#                                                          #  
# Release 3.0.0                                            #  
# Copyright (c) 2005-2008 by Team-PHPRPC                   #  
#                                                          #  
# WebSite:  http://www.phprpc.org/                         #  
#           http://www.phprpc.net/                         #  
#           http://www.phprpc.com/                         #  
#           http://sourceforge.net/projects/php-rpc/       #  
#                                                          #  
# Authors:  Ma Bingyao <andot@ujn.edu.cn>                  #  
#                                                          #  
# This file may be distributed and/or modified under the   #  
# terms of the GNU Lesser General Public License (LGPL)    #  
# version 3.0 as published by the Free Software Foundation #  
# and appearing in the included file LICENSE.              #  
#                                                          #  
############################################################  
#  
# XXTEA encryption arithmetic library.  
#  
# Copyright (C) 2005-2008 Ma Bingyao <andot@ujn.edu.cn>  
# Version: 1.0  
# LastModified: Oct 5, 2008  
# This library is free.  You can redistribute it and/or modify it.  
  
import struct  
  
_DELTA = 0x9E3779B9  
  
def _long2str(v, w):  
    n = (len(v) - 1) << 2  
    if w:  
        m = v[-1]  
        if (m < n - 3) or (m > n): return ''  
        n = m  
    s = struct.pack('<%iL' % len(v), *v)  
    return s[0:n] if w else s  
  
def _str2long(s, w):  
    n = len(s)  
    m = (4 - (n & 3) & 3) + n  
    s = s.ljust(m, "\0")  
    v = list(struct.unpack('<%iL' % (m >> 2), s))  
    if w: v.append(n)  
    return v  
  
def encrypt(str, key):  
    if str == '': return str  
    v = _str2long(str, True)  
    k = _str2long(key.ljust(16, "\0"), False)  
    n = len(v) - 1  
    z = v[n]  
    y = v[0]  
    sum = 0  
    q = 6 + 52 // (n + 1)  
    while q > 0:  
        sum = (sum + _DELTA) & 0xffffffff  
        e = sum >> 2 & 3  
        for p in xrange(n):  
            y = v[p + 1]  
            v[p] = (v[p] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff  
            z = v[p]  
        y = v[0]  
        v[n] = (v[n] + ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[n & 3 ^ e] ^ z))) & 0xffffffff  
        z = v[n]  
        q -= 1  
    return _long2str(v, False)  
  
def decrypt(str, key):  
    if str == '': return str  
    v = _str2long(str, False)  
    k = _str2long(key.ljust(16, "\0"), False)  
    n = len(v) - 1  
    z = v[n]  
    y = v[0]  
    q = 6 + 52 // (n + 1)  
    sum = (q * _DELTA) & 0xffffffff  
    while (sum != 0):  
        e = sum >> 2 & 3  
        for p in xrange(n, 0, -1):  
            z = v[p - 1]  
            v[p] = (v[p] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z))) & 0xffffffff  
            y = v[p]  
        z = v[n]  
        v[0] = (v[0] - ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[0 & 3 ^ e] ^ z))) & 0xffffffff  
        y = v[0]  
        sum = (sum - _DELTA) & 0xffffffff  
    return _long2str(v, True)  
  
if __name__ == "__main__":  
    print decrypt(encrypt('Hello XXTEA!', '16bytelongstring'), '16bytelongstring')  
~~~



原文链接：https://blog.csdn.net/gsls200808/java/article/details/48243019

### write/readfile

~~~c
BOOL WriteFile( 
  HANDLE hFile, 
  LPCVOID lpBuffer, 
  DWORD nNumberOfBytesToWrite, 
  LPDWORD lpNumberOfBytesWritten, 
  LPOVERLAPPED lpOverlapped
); 
/**
参量
hFile
[in]处理要写入的文件。必须已使用GENERIC_WRITE访问该文件的文件句柄。
lpBuffer
[in]指向包含要写入文件的数据的缓冲区的指针。
nNumberOfBytesToWrite
[输入]要写入文件的字节数。

零值表示空写入操作。空写入操作不会写入任何字节，但是会导致时间戳发生变化。此功能不会截断文件。要截断或扩展文件，请使用SetEndOfFile函数。

lpNumberOfBytesWritten
[out]指向此函数调用写入的字节数的指针。在执行操作或检查错误之前，此功能将此值设置为零。
lpOverlapped
[输入]不支持。设置为NULL。
**/
~~~

~~~c
BOOL ReadFile(
  HANDLE hFile,
  LPVOID lpBuffer,
  DWORD nNumberOfBytesToRead,
  LPDWORD lpNumberOfBytesRead,
  LPOVERLAPPED lpOverlapped
);
/**
参量
hFile
[in]处理要读取的文件。必须已使用GENERIC_READ访问该文件的文件句柄。此参数不能是套接字句柄。
lpBuffer
[out]指向缓冲区的指针，该缓冲区接收从文件读取的数据。
nNumberOfBytesToRead
[in]要从文件读取的字节数。
lpNumberOfBytesRead
[out]指向读取的字节数的指针。在执行操作或检查错误之前，此功能将此值设置为零。
lpOverlapped
[输入]不支持。设置为NUL
**/
~~~

### AEH

AddVectoredExceptionHandler function

Registers a vectored exception handler.

+   Syntax

```cpp
PVOID AddVectoredExceptionHandler(
  ULONG                       First,
  PVECTORED_EXCEPTION_HANDLER Handler
);
```

+   Return value

If the function succeeds, the return value is a handle to the exception handler.

If the function fails, the return value is **NULL**.

[异常处理](http://www.manongjc.com/article/36495.html)





### pysm4

pysm4是国密SM4算法的Python实现， 提供了`encrypt`、 `decrypt`、 `encrypt_ecb`、 `decrypt_ecb`、 `encrypt_cbc`、 `decrypt_cbc`等函数用于加密解密， 用法如下：

#### 1. `encrypt`和`decrypt`

```
>>> from pysm4 import encrypt, decrypt
# 明文
>>> clear_num = 0x0123456789abcdeffedcba9876543210
# 密钥
>>> mk = 0x0123456789abcdeffedcba9876543210
# 加密
>>> cipher_num = encrypt(clear_num, mk)
>>> hex(cipher_num)[2:].replace('L', '')
'681edf34d206965e86b3e94f536e4246'
# 解密
>>> clear_num == decrypt(cipher_num, mk)
True
```

#### 2. `encrypt_ecb`和`decrypt_ecb`

```
>>> from pysm4 import encrypt_ecb, decrypt_ecb
# 明文
>>> plain_text = 'pysm4是国密SM4算法的Python实现'
# 密钥
>>> key = 'hello, world!'  # 密钥长度小于等于16字节
# 加密
>>> cipher_text = encrypt_ecb(plain_text, key)
>>> cipher_text
'ng3L4ldgvsZciAgx3LhplDvIzrd0+GXiNqNmd1VW0YOlwo+ojtpownOCbnxbq/3y'
# 解密
>>> plain_text == decrypt_ecb(cipher_text, key)
True
```

#### 3. `encrypt_cbc`和`decrypt_cbc`

```
>>> from pysm4 import encrypt_cbc, decrypt_cbc
# 明文
>>> plain_text = 'pysm4是国密SM4算法的Python实现'
# 密钥
>>> key = 'hello, world!'  # 密钥 长度小于等于16字节
# 初始化向量
>>> iv = '11111111'        # 初始化向量  长度小于等于16字节
# 加密
>>> cipher_text = encrypt_cbc(plain_text, key, iv)
'cTsdKRSH2FqIJf22NHMjX5ZFHghR4ZtJ10wbNwj2//bJSElBXVeMtFycjdlVKP15'
# 解密
>>> plain_text == decrypt_cbc(cipher_text, key, iv)
True
```

### idc

[idc基础](https://blog.csdn.net/jazrynwong/article/details/84875699)

## 附件

### CryptCreateHash:ALG_ID

| Identifier                | Value      | Description                                                  |
| :------------------------ | :--------- | :----------------------------------------------------------- |
| CALG_3DES                 | 0x00006603 | [*Triple DES*](https://docs.microsoft.com/windows/desktop/SecGloss/t-gly) encryption algorithm. |
| CALG_3DES_112             | 0x00006609 | Two-key [*triple DES*](https://docs.microsoft.com/windows/desktop/SecGloss/t-gly) encryption with effective key length equal to 112 bits. |
| CALG_AES                  | 0x00006611 | Advanced Encryption Standard (AES). This algorithm is supported by the [Microsoft AES Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-aes-cryptographic-provider). |
| CALG_AES_128              | 0x0000660e | 128 bit AES. This algorithm is supported by the [Microsoft AES Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-aes-cryptographic-provider). |
| CALG_AES_192              | 0x0000660f | 192 bit AES. This algorithm is supported by the [Microsoft AES Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-aes-cryptographic-provider). |
| CALG_AES_256              | 0x00006610 | 256 bit AES. This algorithm is supported by the [Microsoft AES Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-aes-cryptographic-provider). |
| CALG_AGREEDKEY_ANY        | 0x0000aa03 | Temporary algorithm identifier for handles of Diffie-Hellman–agreed keys. |
| CALG_CYLINK_MEK           | 0x0000660c | An algorithm to create a 40-bit DES key that has parity bits and zeroed key bits to make its key length 64 bits. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_DES                  | 0x00006601 | DES encryption algorithm.                                    |
| CALG_DESX                 | 0x00006604 | DESX encryption algorithm.                                   |
| CALG_DH_EPHEM             | 0x0000aa02 | Diffie-Hellman ephemeral key exchange algorithm.             |
| CALG_DH_SF                | 0x0000aa01 | Diffie-Hellman store and forward key exchange algorithm.     |
| CALG_DSS_SIGN             | 0x00002200 | DSA [*public key*](https://docs.microsoft.com/windows/desktop/SecGloss/p-gly) signature algorithm. |
| CALG_ECDH                 | 0x0000aa05 | Elliptic curve Diffie-Hellman key exchange algorithm.[!Note] This algorithm is supported only through [Cryptography API: Next Generation](https://docs.microsoft.com/windows/desktop/SecCNG/cng-portal). **Windows Server 2003 and Windows XP:** This algorithm is not supported. |
| CALG_ECDH_EPHEM           | 0x0000ae06 | Ephemeral elliptic curve Diffie-Hellman key exchange algorithm.[!Note] This algorithm is supported only through [Cryptography API: Next Generation](https://docs.microsoft.com/windows/desktop/SecCNG/cng-portal). **Windows Server 2003 and Windows XP:** This algorithm is not supported. |
| CALG_ECDSA                | 0x00002203 | Elliptic curve digital signature algorithm.[!Note] This algorithm is supported only through [Cryptography API: Next Generation](https://docs.microsoft.com/windows/desktop/SecCNG/cng-portal). **Windows Server 2003 and Windows XP:** This algorithm is not supported. |
| CALG_ECMQV                | 0x0000a001 | Elliptic curve Menezes, Qu, and Vanstone (MQV) key exchange algorithm. This algorithm is not supported. |
| CALG_HASH_REPLACE_OWF     | 0x0000800b | One way function hashing algorithm.                          |
| CALG_HUGHES_MD5           | 0x0000a003 | Hughes MD5 hashing algorithm.                                |
| CALG_HMAC                 | 0x00008009 | HMAC keyed hash algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_KEA_KEYX             | 0x0000aa04 | KEA key exchange algorithm (FORTEZZA). This algorithm is not supported. |
| CALG_MAC                  | 0x00008005 | [*MAC*](https://docs.microsoft.com/windows/desktop/SecGloss/m-gly) keyed hash algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_MD2                  | 0x00008001 | MD2 hashing algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_MD4                  | 0x00008002 | MD4 hashing algorithm.                                       |
| CALG_MD5                  | 0x00008003 | MD5 hashing algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_NO_SIGN              | 0x00002000 | No signature algorithm.                                      |
| CALG_OID_INFO_CNG_ONLY    | 0xffffffff | The algorithm is only implemented in CNG. The macro, IS_SPECIAL_OID_INFO_ALGID, can be used to determine whether a cryptography algorithm is only supported by using the CNG functions. |
| CALG_OID_INFO_PARAMETERS  | 0xfffffffe | The algorithm is defined in the encoded parameters. The algorithm is only supported by using CNG. The macro, IS_SPECIAL_OID_INFO_ALGID, can be used to determine whether a cryptography algorithm is only supported by using the CNG functions. |
| CALG_PCT1_MASTER          | 0x00004c04 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_RC2                  | 0x00006602 | RC2 block encryption algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_RC4                  | 0x00006801 | RC4 stream encryption algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_RC5                  | 0x0000660d | RC5 block encryption algorithm.                              |
| CALG_RSA_KEYX             | 0x0000a400 | RSA public key exchange algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_RSA_SIGN             | 0x00002400 | RSA public key signature algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_SCHANNEL_ENC_KEY     | 0x00004c07 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_SCHANNEL_MAC_KEY     | 0x00004c03 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_SCHANNEL_MASTER_HASH | 0x00004c02 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_SEAL                 | 0x00006802 | SEAL encryption algorithm. This algorithm is not supported.  |
| CALG_SHA                  | 0x00008004 | SHA hashing algorithm. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_SHA1                 | 0x00008004 | Same as **CALG_SHA**. This algorithm is supported by the [Microsoft Base Cryptographic Provider](https://docs.microsoft.com/zh-cn/windows/win32/seccrypto/microsoft-base-cryptographic-provider). |
| CALG_SHA_256              | 0x0000800c | 256 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider..**Windows XP with SP3:** This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype). **Windows XP with SP2, Windows XP with SP1 and Windows XP:** This algorithm is not supported. |
| CALG_SHA_384              | 0x0000800d | 384 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider.**Windows XP with SP3:** This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype). **Windows XP with SP2, Windows XP with SP1 and Windows XP:** This algorithm is not supported. |
| CALG_SHA_512              | 0x0000800e | 512 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider.**Windows XP with SP3:** This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype). **Windows XP with SP2, Windows XP with SP1 and Windows XP:** This algorithm is not supported. |
| CALG_SKIPJACK             | 0x0000660a | Skipjack block encryption algorithm (FORTEZZA). This algorithm is not supported. |
| CALG_SSL2_MASTER          | 0x00004c05 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_SSL3_MASTER          | 0x00004c01 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_SSL3_SHAMD5          | 0x00008008 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_TEK                  | 0x0000660b | TEK (FORTEZZA). This algorithm is not supported.             |
| CALG_TLS1_MASTER          | 0x00004c06 | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |
| CALG_TLS1PRF              | 0x0000800a | Used by the Schannel.dll operations system. This **ALG_ID** should not be used by applications. |