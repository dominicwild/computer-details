# Computer Details
An electron application used for getting basic details about a device. This is used to get diagnostic information on a machine for an overview of the system. Can be used for sysadmin jobs to speed up determining problems with configuration.

## PowerShell Interaction
Uses PowerShell behind the scenes of an eletron application to pull data about the system and render it into HTML, which electron then displays. This is cached, as gathering some information can be quite intensive on low performance machines.

## Output File
Clicking the "all info" button will show all the information across all the tabs and output a file on the desktop showing the details of the machine. An example can be [found here](docs\example\files\allData.txt)

## Miscellaneous Functions
A button to empty the recylcing bin and clean up various junk files to free up disk space is present. All these use PowerShell in the background to conduct these tasks. Leaves room for further functions to have possibly been added.

---

# Screenshots
More screenshots can be found [here](docs\img).
## Operating System
![Operating System UI](docs\img\Operating-System.png)

## NIC
![NIC Information UI](docs\img\NIC-Information.png)