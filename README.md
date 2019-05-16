# pwospf

Project for the Master in Software and Data Engineering course "Advanced Networking: Build an Internet Router".

## What is missing

-   LSU variable size
-   LSU update with meaningful routes (i.e. not hardcoded)
-   LSU packet handling
-   Timers for hello packet

To complete the LSU handling I needed meaningful routes in the LSU but as I explain below the IP format is wrong and I can't do much with it.

## What is working

My implementation has many aspects of the pwospf specification simplified. I have tested the routing table with only 3 switches but it seems to work.
The switches can send and receive meaningful hello packet and adjust the routing table inserting the neighbours accordingly, the link state update are created with a fixed size and only one LSU for packet. They are parsed correctly but I'm missing part of the controller that would be needed to translate the "10.0.0.1" IP format into an int that should fit inside the LSU Subnet field inside the packet.
I also have a forwarding table in the controller that translate addresses to forwarding ports.

I probably would need for the final implementation a different kind of forwarding table as I'm using the addresses to identify the routes and that is not ideal.
