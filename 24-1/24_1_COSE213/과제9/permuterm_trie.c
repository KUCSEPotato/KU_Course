#include <stdio.h>
#include <stdlib.h> // malloc, free
#include <string.h> // strdup, strchr, sprintf
#include <ctype.h>  // isupper, tolower

#define MAX_DEGREE 27 // 'a' ~ 'z' and EOW
#define EOW         '$' // end of word

// used in the following functions: trieInsert, trieSearch, triePrefixList
#define getIndex(x) (((x) == EOW) ? MAX_DEGREE - 1 : ((x) - 'a'))

// TRIE type definition
typedef struct trieNode {
    int index; // -1 (non-word), 0, 1, 2, ...
    struct trieNode *subtrees[MAX_DEGREE];
} TRIE;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// Prototype declarations

/* Allocates dynamic memory for a trie node and returns its address to caller
   return  node pointer
           NULL if overflow
*/
TRIE *trieCreateNode(void) {
    TRIE *newnode = (TRIE *)malloc(sizeof(TRIE));
    if (!newnode) return NULL;

    newnode->index = -1;
    for (int i = 0; i < MAX_DEGREE; i++) {
        newnode->subtrees[i] = NULL;
    }

    return newnode;
}

/* Deletes all data in trie and recycles memory
*/
void trieDestroy(TRIE *root) {
    if (!root) return;

    for (int i = 0; i < MAX_DEGREE; i++) {
        if (root->subtrees[i]) {
            trieDestroy(root->subtrees[i]);
        }
    }
    free(root);
}

/* Inserts new entry into the trie
   return 1 success
          0 failure
*/
// 주의! 엔트리를 중복 삽입하지 않도록 체크해야 함
// 대소문자를 소문자로 통일하여 삽입
// 영문자와 EOW 외 문자를 포함하는 문자열은 삽입하지 않음
int trieInsert(TRIE *root, char *str, int dic_index) {
    if (!root) return 0;

    TRIE *current = root;
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];
        if (isupper(c)) c = tolower(c);

        int idx = getIndex(c);
        if (idx < 0 || idx >= MAX_DEGREE) return 0; // Invalid character

        if (!current->subtrees[idx]) {
            current->subtrees[idx] = trieCreateNode();
        }
        current = current->subtrees[idx];
    }

    if (current->index == -1) { // Ensure not duplicate
        current->index = dic_index;
        return 1;
    }

    return 0; // Duplicate entry
}

/* Retrieve trie for the requested key
   return  index in dictionary (trie) if key found
           -1 key not found
*/
int trieSearch(TRIE *root, char *str) {
    if (!root) return -1;

    // Append EOW to the search string to match insertion format
    int len = strlen(str);
    char *searchStr = (char *)malloc(len + 2); // Allocate space for str + '$' + '\0'
    if (!searchStr) return -1; // Check allocation success
    sprintf(searchStr, "%s%c", str, EOW); // Append EOW

    TRIE *current = root;
    for (int i = 0; searchStr[i] != '\0'; i++) {
        char c = searchStr[i];
        if (isupper(c)) c = tolower(c); // Convert to lowercase

        int idx = getIndex(c);
        if (idx < 0 || idx >= MAX_DEGREE) { // Invalid character
            free(searchStr);
            return -1; // Exit with error
        }

        if (!current->subtrees[idx]) {
            free(searchStr);
            return -1; // Not found
        }
        current = current->subtrees[idx];
    }

    int result = current->index;
    free(searchStr); // Clean up allocated memory
    return result;
}

static int trieList_main(TRIE *root, char *dic[], int count) {
    if (root == NULL) return count;

    if (root->index != -1) {
        printf("[%d]%s\n", count + 1, dic[root->index]);
        count++;
    }

    for (int i = 0; i < MAX_DEGREE; i++) {
        if (root->subtrees[i]) {
            count = trieList_main(root->subtrees[i], dic, count);
        }
    }
    return count;
}

/* prints all entries in trie using preorder traversal
*/
void trieList(TRIE *root, char *dic[]) {
    if (root == NULL) return;

    trieList_main(root, dic, 0);
}

/* prints all entries starting with str (as prefix) in trie
   ex) "ab" -> "abandoned", "abandoning", "abandonment", "abased", ...
   this function uses trieList function
*/
void triePrefixList(TRIE *root, char *str, char *dic[]) {
    if (!root) return;

    TRIE *current = root;
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];
        if (isupper(c)) c = tolower(c);

        int idx = getIndex(c);
        if (idx < 0 || idx >= MAX_DEGREE) return; // Invalid character

        if (!current->subtrees[idx]) {
            return; // Prefix not found
        }
        current = current->subtrees[idx];
    }

    trieList(current, dic);
}

/* makes permuterms for given str
   ex) "abc" -> "abc$", "bc$a", "c$ab", "$abc"
   return  number of permuterms
*/
int make_permuterms(char *str, char *permuterms[]) {
    int len = strlen(str);
    char *buffer = (char *)malloc(len + 2); // +1 for $, +1 for \0
    if (!buffer) return 0;

    sprintf(buffer, "%s%c", str, EOW);
    int count = 0;
    for (int i = 0; i <= len; i++) {
        permuterms[count] = strdup(buffer);
        if (!permuterms[count]) break;
        count++;

        // Rotate the string left by 1
        char temp = buffer[0];
        memmove(buffer, buffer + 1, len);
        buffer[len] = temp;
    }

    free(buffer);
    return count;
}

/* recycles memory for permuterms
*/
void clear_permuterms(char *permuterms[], int size) {
    for (int i = 0; i < size; i++) {
        if (permuterms[i]) {
            free(permuterms[i]);
            permuterms[i] = NULL;
        }
    }
}

/* wildcard search
   ex) "ab*", "*ab", "a*b", "*ab*"
   this function uses triePrefixList function
*/
void trieSearchWildcard( TRIE *root, char *str, char *dic[]){
    char per[100], tmp;
    int len = strlen(str);

    strcpy(per,str);
    per[len] = EOW;
    per[len+1] = '\0';

    for(int i = 0 ; i <= len ; i++){
        tmp = per[0];
        memmove(per,per+1,sizeof(char)*len);
        per[len] = tmp;

        if(per[len] == '*'){
            per[strchr(per,'*') - per] = '\0';
            triePrefixList(root,per,dic);
            break;
        }
    }
}


////////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv) {
    TRIE *permute_trie;
    char *dic[100000];

    int ret;
    char str[100];
    FILE *fp;
    char *permuterms[100];
    int num_p; // # of permuterms
    int num_words = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s FILE\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "rt");
    if (fp == NULL) {
        fprintf(stderr, "File open error: %s\n", argv[1]);
        return 1;
    }

    permute_trie = trieCreateNode(); // trie for permuterm index

    while (fscanf(fp, "%s", str) != EOF) {
        num_p = make_permuterms(str, permuterms);

        for (int i = 0; i < num_p; i++) {
            trieInsert(permute_trie, permuterms[i], num_words);
        }

        clear_permuterms(permuterms, num_p);

        dic[num_words++] = strdup(str);
    }

    fclose(fp);

    printf("\nQuery: ");
    while (fscanf(stdin, "%s", str) != EOF) {
        // wildcard search term
        if (strchr(str, '*')) {
            trieSearchWildcard(permute_trie, str, dic);
        }
        // keyword search
        else {
            ret = trieSearch(permute_trie, str);

            if (ret == -1) {
                printf("[%s] not found!\n", str);
            } else {
                printf("[%s] found!\n", dic[ret]);
            }
        }
        printf("\nQuery: ");
    }

    for (int i = 0; i < num_words; i++) {
        free(dic[i]);
    }

    trieDestroy(permute_trie);

    return 0;
}
