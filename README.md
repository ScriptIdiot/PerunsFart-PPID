# PerunsFart-PPID
Userland API hooking bypass with modified PerunsFart
1. CreateProcess with PPID spoofing in suspended state
2. Replace current hooked syscall table with unhooked syscall table in the created process

#### PerunsFart without PPID spoofed
![image](https://user-images.githubusercontent.com/21979646/177043214-50bccaff-f88e-4231-8118-57f9d8781e1c.png)

#### PerunsFart with PPID spoofed
![image](https://user-images.githubusercontent.com/21979646/177043222-e6e4cffd-c7ae-4532-8a3b-7611e7113b40.png)

## Credits

#### PerunsFart
- SEKTOR7

#### CreateProcessA with PPID spoofed
- https://github.com/hlldz/APC-PPID
