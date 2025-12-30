#include <stdio.h>
#include <stdlib.h> // malloc, realloc, free

#include "adt_heap.h"

/* Reestablishes heap by moving data in child up to correct location heap array
   for heap_Insert function
*/
/*부모 노드랑 값 비교시 부모 노드보다 크면 두 위치를 바꿔야함.*/
static void _reheapUp( HEAP *heap, int index) {
   int cmp = heap->compare(heap->heapArr[index], heap->heapArr[(index-1)/2]);
   
   while(index > 0 && cmp > 0) {
         void *temp = NULL;
         temp = heap->heapArr[index];
         heap->heapArr[index] = heap->heapArr[(index-1)/2];
         heap->heapArr[(index-1)/2] = temp;
         index = (index - 1) / 2;

      cmp = heap->compare(heap->heapArr[index], heap->heapArr[(index-1)/2]);
   }  
}

/* Reestablishes heap by moving data in root down to its correct location in the heap
   for heap_Delete function
*/
static void _reheapDown(HEAP *heap, int index) {
   int leftChild, rightChild, largerChild;
   void *temp;

   while ((leftChild = 2 * index + 1) <= heap->last) {
      rightChild = leftChild + 1;
      if (rightChild <= heap->last && heap->compare(heap->heapArr[rightChild], heap->heapArr[leftChild]) > 0) {
         largerChild = rightChild;
      } 
      else {
         largerChild = leftChild;
      }

      if (heap->compare(heap->heapArr[index], heap->heapArr[largerChild]) >= 0) break;

      // 요소들 교환
      temp = heap->heapArr[index];
      heap->heapArr[index] = heap->heapArr[largerChild];
      heap->heapArr[largerChild] = temp;

      index = largerChild;
   }
}


/* Allocates memory for heap and returns address of heap head structure
if memory overflow, NULL returned
The initial capacity of the heap should be 10
*/
HEAP *heap_Create(int (*compare) (const void *arg1, const void *arg2)) {
   HEAP *Heap_Head = (HEAP *)malloc(sizeof(HEAP));
   if (!Heap_Head) return NULL;
   
   Heap_Head->capacity = 10;
   Heap_Head->last = -1; // Assuming last is an index, typically -1 for an empty heap
   Heap_Head->heapArr = (void **)malloc(sizeof(void *) * Heap_Head->capacity);
   if (!Heap_Head->heapArr) {
      free(Heap_Head);
      return NULL;
   }
   Heap_Head->compare = compare;
   
   return Heap_Head;
}

/* Free memory for heap */
void heap_Destroy(HEAP *heap, void (*remove_data)(void *ptr)) {
   if (remove_data) {
      for (int i = 0; i <= heap->last; i++) {
         remove_data(heap->heapArr[i]);  // Use the provided function to free each item
      }
   }
   free(heap->heapArr);  // Free the array of pointers
   free(heap);           // Finally, free the heap structure itself
}


/* Inserts data into heap
return 1 if successful; 0 if heap full
*/
int heap_Insert(HEAP *heap, void *dataPtr) {
   if (heap->last + 1 >= heap->capacity) {
      void **newHeapArr = realloc(heap->heapArr, sizeof(void *) * (heap->capacity * 2));
      if (!newHeapArr) {
         fprintf(stderr, "Memory reallocation failed\n");
         return 0;
      }
      heap->heapArr = newHeapArr;
      heap->capacity = (heap->capacity) * 2;
   }

   heap->last++;
   heap->heapArr[heap->last] = dataPtr;
   _reheapUp(heap, heap->last);

   return 1;
}

/* Deletes root of heap and passes data back to caller
return 1 if successful; 0 if heap empty
*/
int heap_Delete( HEAP *heap, void **dataOutPtr) {
   if (heap_Empty(heap)) return 0;

      *dataOutPtr = heap->heapArr[0];
      heap->heapArr[0] = heap->heapArr[heap->last];
      heap->last--;
      _reheapDown(heap, 0);

      return 1;
   
}

/*
return 1 if the heap is empty; 0 if not
*/
int heap_Empty(  HEAP *heap) {
   if (heap->last == -1) return 1;
   else return 0;
}

/* Print heap array */
void heap_Print( HEAP *heap, void (*print_func) (const void *data)) {
   for (int i = 0; i <= heap->last; i++)
   {
      print_func(heap->heapArr[i]);
   }
}