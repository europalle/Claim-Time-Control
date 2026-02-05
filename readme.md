# Claim Time control

A simple script for personal use, AI Slop cleaned up, and then converted by me. Currently messsing with OOP, so that's why it's overcomplicated and I'm using classes. It's just. I'm weird. I like torturing myself, and as my current curiculum covers Object Oriented Programming, I decided to do it in a script that in no way benefits from the complexity. But it works!

Also, the pre-reqs to run this is the export the chats in a very specific way, with a browser extension, so... Uhm... Good luck? 


## Functionality:
1. Checks logs from a specific file, to measure time between /claims
2. If 1 person has done 2 /claims on 2 different servers in >5 minutes, it counts it as a breach.
3. Displays breaches in the terminal output, and exports the results to a .csv file.


## Tutorial:
-b (--breach) : Counts breaches. Standard and original functionality

-s (--stats) : counts top stats ( amounts of calladmins taken within the period defined). Counts dumb, so if you give it 20 years of logs, it'll count all activity in those 20 years. Haven't implemented any logic into it yet


## To do:
 - Clean up script more. As the OG script is AI slop fest to give me a quick template and starting ground, I'm yet to clean up everything (sorry)
 - Expand on stats functionality, adding filters and/or arguments. Also month-by-month detection built in
 - Add a way to ensure it shows in local time (currently when I have to dig for breaches to ensure it's corect, i gotta go an hour forward. So timestamps are a little iffy)
 - Add easter eggs (maybe a nyan cat?)
 