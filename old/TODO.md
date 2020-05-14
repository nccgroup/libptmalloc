# TODO:

 - we use a hack for free fast chunks. It is because when a fast chunk (i.e. small chunk)
   is free, it is not added to any freelist but instead added to the fastbin so it does
   not have any BIT set in the chunk to realise it is free or not (as we don't want to
   coalesce it). So our hax for now is to look at the 3rd QWORD (after prev_size and size)
   and if it is not an mh_magic (0xa11c0123) then we know it is not allocated
   it is a hax as it is related to libmempool.py. The right way of doing it would be to
   check at the fastbin to see if it is there.

 - when you run ptchunk without any arg, it should print the legend for
   P=PREV_INUSE, M=MMAPED, N=NON_MAIN_ARENA, etc.
