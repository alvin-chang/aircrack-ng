# Fix for airodump-ng Mutex Issue on macOS

## Problem
When running airodump-ng on macOS, users experienced the following error:
```
pthread_mutex_lock.c:83: pthread_mutex_lock: Assertion `mutex->m_owner == 0' failed
```

This was followed by a crash with:
```
Aborted (core dumped)
```

## Root Cause
The issue was in the initialization order in `src/airodump-ng/airodump-ng.c`:

1. Mutexes were initialized early in the main function
2. Later, `memset(&lopt, 0, sizeof(lopt))` was called, which zeroed out the entire `lopt` structure
3. This included the mutexes, corrupting their state
4. When the input thread tried to use these corrupted mutexes, it caused the assertion failure

## Solution
We moved the mutex initialization to occur AFTER the `memset` calls, ensuring that the mutexes are properly initialized after the structures are zeroed out.

### Changes Made:

1. Moved mutex initialization from lines 6043-6044 to after line 6052 (after `memset` calls)
2. Removed the error-prone error handling in the input_thread function and replaced it with proper `ALLEGE` macros

### Before (problematic):
```c
ALLEGE(pthread_mutex_init(&(lopt.mx_print), NULL) == 0);
ALLEGE(pthread_mutex_init(&(lopt.mx_sort), NULL) == 0);

// ... later ...
memset(&lopt, 0, sizeof(lopt));  // This zeroed out the initialized mutexes!
```

### After (fixed):
```c
memset(&lopt, 0, sizeof(lopt));  // Zero out structures first

// Initialize mutexes AFTER zeroing out lopt structure
ALLEGE(pthread_mutex_init(&(lopt.mx_print), NULL) == 0);
ALLEGE(pthread_mutex_init(&(lopt.mx_sort), NULL) == 0);
```

## Testing
The fix has been tested and airodump-ng now runs correctly on macOS without the mutex assertion failure.

## Additional Notes
This fix ensures that:
1. Mutexes are properly initialized after the structures they're part of are zeroed out
2. Error checking is done properly with the ALLEGE macro which will abort with a clear error message if mutex operations fail
3. The fix is minimal and doesn't change the overall program flow or functionality