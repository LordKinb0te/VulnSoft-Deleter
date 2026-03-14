Hooray I can finally retire Sophos! The bullspit AV solution that my malware can bypass without thinking about a AMSI bypasses (not OK Sophos!!!!)

But when I deploy Field Effect MDR, it's going to freak out about vulnerable software on machines pretty much every day. It's also going to yell about roaming profiles syncing vulnerable software down to machines..

As much as I push for it, leadership is not interested in the costs associated with a solution like Intune. But I still can't have vulnerable software sitting on workstations and my roaming profiles store.

First things first, let's purge vulnerable software from local and roaming profiles all in one go. We can specify our target applications along with their unique paths, keys, and scheduled tasks in json, then shoot the shooter script.

I am leaving this script defanged - if you have a use for the script I'm sure you can read the code to stop using WhatIf mode.

After vulnerable software has been purged from the domain, we can use another custom script + a GPO scheduled task so that all domain-joined workstations have up to date software and a fresh restart to begin the business day.

Now Field Effect should stop yelling about as much vulnerable software, our purge+update method gets ahead of CVEs as their signatures become known, and we aren't spending a bunch of money on things like Intune!

Even tho I very much disagree with not purchasing a Microsoft solution for this problem :)
