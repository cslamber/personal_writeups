# tracing (easy) (pwn): 79 solves, 151 points

In tracing, we're given the source to a Rust 'contact tracing' app with its
own hand-rolled implementation of a binary search tree---notably not self-
balancing.  The description tells us that it 'is configured with some sensitive data',
which immediately lends itself to the idea that we're going to be making
the BST unbalanced and running a timing attack.

The server sends you when it finishes inserting everything you put in, as well as when
it finishes looking up a sensitive bytestring in it, so this is the timing differential
we care about.  All we do is we binary search down what that bytestring is by prepping
the BST with data that will take a long time to traverse if their bytestring is greater
than some amount we're checking.

The current code was an ultra inconsistent leak,
but I managed to get out a `CT`, so I gave it the rest of the `CTF{`, and it gave back
(after enough fiddling) `1Bit(A/B)`, which I guessed was `CTF{1BitAtATime}` (so I wouldn't
have to do with more long annoying leaks), and that was correct.

