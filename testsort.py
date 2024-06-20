test_dict = {'Nikhil' : { 'roll' : 24, 'marks' : 17},
             'Akshat' : {'roll' : 54, 'marks' : 12}, 
             'Akash' : { 'roll' : 12, 'marks' : 15}}
 
# printing original dict
print("The original dictionary : " + str(test_dict))
 
# using sorted()
# Sort nested dictionary by key
res = sorted(test_dict.items(), key = lambda x: x[1]['marks'])
 
 
print("==================")
print("itemized dict:") 
print(test_dict.items())
print("==================")


# print result
print("The sorted dictionary by marks is : " + str(res))