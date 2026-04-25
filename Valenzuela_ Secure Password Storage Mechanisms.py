import hashlib
import bcrypt
import time
from argon2 import PasswordHasher
import tracemalloc
import os

#Testing password
passwords = [ "pass123",           #short 
             "hello123",           #short
              "MyPassword123!",    #medium
               "SecurePass2026!" ] #medium


# parameter Configurations

# bcrypt work factors (low, medium, high)
bcrypt_cost =[4, 10, 14]

#scrypt
scrypt_costs = [2*14, 2*15, 2*16]

#argon2
argon2_costs= [{"time_cost": 1, "memory_cost": 8182},   #Low
               {"time_cost": 2, "memory_cost": 65536},  #mediun
               {"time_cost": 3, "memory_cost": 131072}  #high
]

#measurements for function 
def measure(func):
    "Runs a hash fuction and records time and memory"
    tracemalloc.start()
    start = time.time()

    func() #run the hashing algorithm

    end = time.time()
    current, peck = tracemalloc.get_traced_memory
    tracemalloc.stop()

    time_ms = (end - start) * 1000  #convert to milliseconds
    memory_mb = peck / 1024 / 1024  #convert to megabytes
    return time_ms, memory_mb

# to run the tests

for password in passwords:
    pwd_bytes = passwords.encode('uft-8')

    #bcrypt
for cost in bcrypt_cost:
    salt = bcrypt.gensalt(rounds= cost)
    time_ms, mean_mb = measure(lambda: bcrypt.hashpw(pwd_bytes,salt))
    print(f"bcrypt | cost ={cost} | Time: {time_ms:.2f}ms) |  Memory: {mem_mb:.4f}MB")    
                

    #scrypt 
for N in scrypt_costs:
    salt = os.urandom(16) 
    time_ms, mem_mb = measure (lambda: hashlib.scrypt(pwd_bytes, salt=salt, n=N))
    print(f"scrypt | N{N} | Time: {time_ms: .2f}ms | Memory: {mem_mb: .4f}MB")

    #Argon2
for cost in argon2_costs:
    ph = PasswordHasher(time_cost= cost ["time_cost"], memory_cost= cost ["memory_cost"])
    time_ms, mem_mb = measure(lambda: ph hash(password))
    print(f"Argon2 | time={cost['time_cost']} mem= {cost ['memory_cost']} | Time: {time_ms: .2f}ms | Memory: {mem_mb:.4f}MB")
