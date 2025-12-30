#include <stdio.h>
#include <stdlib.h> // malloc, realloc, free, qsort
#include <string.h> // strdup, strcmp, memmove

#define SORT_BY_WORD	0 // 단어 순 정렬
#define SORT_BY_FREQ	1 // 빈도 순 정렬

// 구조체 선언
// 단어 구조체
typedef struct {
	char	*word;		// 단어
	int		freq;		// 빈도
} tWord;

// 사전(dictionary) 구조체
typedef struct {
	int		len;		// 배열에 저장된 단어의 수
	int		capacity;	// 배열의 용량 (배열에 저장 가능한 단어의 수)
	tWord	*data;		// 단어 구조체 배열에 대한 포인터
} tWordDic;

////////////////////////////////////////////////////////////////////////////////
// 함수 원형 선언(declaration)

// 단어를 사전에 저장
// 새로 등장한 단어는 사전에 추가
// 이미 사전에 존재하는(저장된) 단어는 해당 단어의 빈도를 갱신(update)
// capacity는 1000으로부터 시작하여 1000씩 증가 (1000, 2000, 3000, ...)
void word_count( FILE *fp, tWordDic *dic);

// 사전을 화면에 출력 ("단어\t빈도" 형식)
void print_dic( tWordDic *dic);

// 사전에 할당된 메모리를 해제
void destroy_dic(tWordDic *dic);

// qsort를 위한 비교 함수
// 정렬 기준 : 단어
int compare_by_word( const void *n1, const void *n2);

// 정렬 기준 : 빈도 내림차순(1순위), 단어(2순위)
int compare_by_freq( const void *n1, const void *n2);

////////////////////////////////////////////////////////////////////////////////
// 이진탐색 함수
// found : key가 발견되는 경우 1, key가 발견되지 않는 경우 0
// return value: key가 발견되는 경우, 배열의 인덱스
//				key가 발견되지 않는 경우, key가 삽입되어야 할 배열의 인덱스
int binary_search( const void *key, const void *base, size_t nmemb, size_t size, 
				int (*compare)(const void *, const void *), int *found);
				
////////////////////////////////////////////////////////////////////////////////
// 함수 정의 (definition)

// 사전을 초기화 (빈 사전을 생성, 메모리 할당)
// len를 0으로, capacity를 1000으로 초기화
// return : 구조체 포인터
tWordDic *create_dic(void)
{
	tWordDic *dic = (tWordDic *)malloc( sizeof(tWordDic));
	
	dic->len = 0;
	dic->capacity = 1000;
	dic->data = (tWord *)malloc(dic->capacity * sizeof(tWord));

	return dic;
}

////////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
	tWordDic *dic;
	int option;
	FILE *fp;
	
	if (argc != 3)
	{
		fprintf( stderr, "Usage: %s option FILE\n\n", argv[0]);
		fprintf( stderr, "option\n\t-n\t\tsort by word\n\t-f\t\tsort by frequency\n");
		return 1;
	}
	
	if (strcmp( argv[1], "-n") == 0) option = SORT_BY_WORD;
	else if (strcmp( argv[1], "-f") == 0) option = SORT_BY_FREQ;
	else {
		fprintf( stderr, "unknown option : %s\n", argv[1]);
		return 1;
	}
	
	// 사전 초기화
	dic = create_dic();

	// 입력 파일 열기
	if ((fp = fopen( argv[2], "r")) == NULL) 
	{
		fprintf( stderr, "cannot open file : %s\n", argv[2]);
		return 1;
	}

	// 입력 파일로부터 단어와 빈도를 사전에 저장
	word_count( fp, dic);

	fclose( fp);

	// 정렬 (빈도 내림차순, 빈도가 같은 경우 단어순)
	if (option == SORT_BY_FREQ) {
		qsort( dic->data, dic->len, sizeof(tWord), compare_by_freq);
	}
		
	// 사전을 화면에 출력
	print_dic( dic);

	// 사전 메모리 해제
	destroy_dic( dic);
	
	return 0;
}

void word_count( FILE *fp, tWordDic *dic)
{
	int found = 0;
	char buffer[100];
	int index = 0;
	tWord temp;

	while (fscanf(fp, "%s", buffer) != EOF)
	{
		temp.word = strdup(buffer);

		if (dic->capacity == dic->len) 
		{
			dic->capacity += 1000;
			dic->data = (tWord*)realloc(dic->data, dic->capacity * sizeof(tWord));
		}
		if (dic->data == NULL)
		{
			printf("Memory allocation failed!\n");
			exit(1);
		}

		if (dic -> len == 0)
		{
			dic->data[dic->len].word = strdup(buffer);
			dic->data[dic->len].freq = 1;
			dic -> len++;
		}
		else
		{
			index = binary_search(&temp, dic, dic->len, sizeof(tWord), compare_by_word, &found);

			if (!found) // temp가 존재하지 않는 경우 -> 사전에 추가
			{
				memmove(dic->data + index + 1, dic->data + index,(dic->len - index) * sizeof(tWord)); 
				dic->data[index].word = strdup(buffer);
				dic->data[index].freq = 1;
				dic->len++;
			}
			else // temp가 존재하는 경우
			{
				dic->data[index].freq++; 
			}
		}
	}
	

}

void print_dic( tWordDic *dic)
{
	for (int i = 0; i < dic->len; i++)
	{
		printf("%s\t%d\n", dic->data[i].word, dic->data[i].freq);
	}
}

void destroy_dic(tWordDic *dic)
{
	for (int i = 0; i < dic -> len; i++)
	{
		free(dic->data[i].word);
	}
	free(dic->data);
	free(dic);
}

//단어순 정렬
int compare_by_word( const void *n1, const void *n2)
{
	const tWord *word1 = (const tWord *)n1;
	const tWord *word2 = (const tWord *)n2;

	return strcmp(word1->word, word2->word);
}

// 단어 빈도순 정렬
int compare_by_freq( const void *n1, const void *n2)
{
	const tWord *word1 = (const tWord *)n1;
	const tWord *word2 = (const tWord *)n2;

	if (word1->freq != word2->freq) return (word2->freq) - (word1->freq);
	else return strcmp(word1->word, word2->word);
}

// 이진탐색
// found : key가 발견되는 경우 1, key가 발견되지 않는 경우 0 // 배열안에 이 elem이 있는지 없는지 알기 위해서.
// return value: key가 발견되는 경우, 배열의 인덱스
// key가 발견되지 않는 경우, key가 삽입되어야 할 배열의 인덱스
int binary_search( const void *key, const void *base, size_t nmemb, size_t size, int (*compare)(const void *, const void *), int *found)
{
	int left = 0;
	int right = nmemb - 1; // 배열 전달 받는 것이기 때문에 index에서 1 빼줘야함.
	int mid;
	int cmpres;
	int *binary_found = found;
	tWord *temp = (tWord *)key;
	tWordDic *array = (tWordDic *)base;

	while (left <= right)
	{
		mid = (left + right) / 2;
		cmpres = strcmp(temp->word, array->data[mid].word);

		if (cmpres == 0)
		{
			*binary_found = 1;
			return mid;
		}
		else
		{
			if (cmpres < 0)
			{
				right = mid - 1;
			}
			else
			{
				left = mid + 1;
			}
		}
	}

	*binary_found = 0;

	return left; // 삽입할 위치 반환
}
				