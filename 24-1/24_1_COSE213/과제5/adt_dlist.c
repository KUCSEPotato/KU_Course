#include <stdlib.h> // malloc
#include "adt_dlist.h"

////////////////////////////////////////////////////////////////////////////////
// function declarations

// Allocates dynamic memory for a list head node and returns its address to caller
// return  head node pointer
//         NULL if overflow
LIST *createList(int (*compare)(const void *, const void *)) {
    LIST *HeadNode = (LIST *)malloc(sizeof(LIST));
    if (HeadNode == NULL) exit(1);

    HeadNode->head = NULL;
    HeadNode->rear = NULL;
    HeadNode->count = 0;
    HeadNode->compare = compare;

    return HeadNode;
}

// Frees memory allocated for the list (head node, data node)
void destroyList(LIST *pList, void (*callback)(void *)) {
    if (pList == NULL) return;

    NODE *temp = pList->head;
    while (temp != NULL) {
        NODE *next = temp->rlink;
        callback(temp->dataPtr);
        free(temp);
        temp = next;
    }
    free(pList); 
}

// Inserts data into list
// callback is a function to be called when a duplicate is found
// return  0 if overflow
//         1 if successful
//         2 if duplicated key
int addNode(LIST *pList, void *dataInPtr, void (*callback)(const void *)) {
    NODE *pPre = NULL;
    NODE *pLoc = pList->head;

    // Locate the position to insert
    while (pLoc != NULL && pList->compare(dataInPtr, pLoc->dataPtr) > 0) {
        pPre = pLoc;
        pLoc = pLoc->rlink;
    }

    // Check for duplication
    if (pLoc != NULL && pList->compare(dataInPtr, pLoc->dataPtr) == 0) {
        callback(pLoc->dataPtr);
        return 2;
    }

    // Create a new node
    NODE *pNew = (NODE *)malloc(sizeof(NODE));
    if (pNew == NULL) {
        return 0;
    }
    pNew->dataPtr = dataInPtr;
    pNew->llink = NULL;
    pNew->rlink = NULL;

    // Insert the new node into the list
    if (pPre == NULL) { // Insert at the beginning
        pNew->rlink = pList->head;
        if (pList->head != NULL) {
            pList->head->llink = pNew;
        } else {
            pList->rear = pNew;
        }
        pList->head = pNew;
    } else { // Insert in the middle or end
        pNew->rlink = pPre->rlink;
        pNew->llink = pPre;
        if (pPre->rlink != NULL) {
            pPre->rlink->llink = pNew;
        } else {
            pList->rear = pNew;
        }
        pPre->rlink = pNew;
    }

    pList->count++;
    return 1;
}

// Removes data from list
// return  0 not found
//         1 deleted
int removeNode(LIST *pList, void *keyPtr, void **dataOutPtr) {
    NODE *pLoc = pList->head;

    // Locate the node to be removed
    while (pLoc != NULL && pList->compare(keyPtr, pLoc->dataPtr) != 0) {
        pLoc = pLoc->rlink;
    }

    if (pLoc == NULL) {
        return 0;
    }

    if (pLoc->llink == NULL) { // Removing the first node
        pList->head = pLoc->rlink;
        if (pList->head != NULL) {
            pList->head->llink = NULL;
        } else {
            pList->rear = NULL;
        }
    } else if (pLoc->rlink == NULL) { // Removing the last node
        pLoc->llink->rlink = NULL;
        pList->rear = pLoc->llink;
    } else { // Removing a middle node
        pLoc->llink->rlink = pLoc->rlink;
        pLoc->rlink->llink = pLoc->llink;
    }

    *dataOutPtr = pLoc->dataPtr;
    free(pLoc);
    pList->count--;
    return 1;
}

// Searches for a node in the list
// return  1 if found
//         0 if not found
int searchNode(LIST *pList, void *pArgu, void **dataOutPtr) {
    NODE *pLoc = pList->head;

    while (pLoc != NULL) {
        int cmp = pList->compare(pArgu, pLoc->dataPtr);
        if (cmp == 0) {
            *dataOutPtr = pLoc->dataPtr;
            return 1;
        } else if (cmp < 0) {
            break;
        }
        pLoc = pLoc->rlink;
    }

    return 0;
}

// Returns the number of nodes in the list
int countList(LIST *pList) {
    return pList->count;
}

// Checks if the list is empty
// return  1 if empty
//         0 if not empty
int emptyList(LIST *pList) {
    return (pList->count == 0);
}

// Traverses the list from head to tail
void traverseList(LIST *pList, void (*callback)(const void *)) {
    NODE *temp = pList->head;
    while (temp != NULL) {
        callback(temp->dataPtr);
        temp = temp->rlink;
    }
}

// Traverses the list from tail to head
void traverseListR(LIST *pList, void (*callback)(const void *)) {
    NODE *temp = pList->rear;
    while (temp != NULL) {
        callback(temp->dataPtr);
        temp = temp->llink;
    }
}

