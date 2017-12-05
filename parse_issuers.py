import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from functools import reduce

no_of_certs = dict()

with open('issuers.txt', 'r') as f:
    for name in f.readlines():
        name = name.rstrip("\n\r")
        ca_certs_list = name.split(": ")
        ca_certs_list[0] = ca_certs_list[0].split(" ")[0]
        # some custom fixes
        if ca_certs_list[0] == "Go":
            ca_certs_list[0] = "Go Daddy"
        elif ca_certs_list[0] == "thawte":
            ca_certs_list[0] = "Thawte"

        if ca_certs_list[0] in no_of_certs:
            no_of_certs[ca_certs_list[0]] += int(ca_certs_list[1])
        else:
            no_of_certs[ca_certs_list[0]] = int(ca_certs_list[1])

for key in sorted(no_of_certs, key=no_of_certs.get, reverse=True):
    print("CA Issuer: {0}, No of issues: {1}".format(key, no_of_certs[key]))

with open('issuers_condensed.csv', 'w') as f:
    # f.write("CA, No_of_certs_issued\n")
    for key in sorted(no_of_certs, key=no_of_certs.get, reverse=True):
        f.write(key + ", " + str(no_of_certs[key]) + "\n")

# Seaborn plot
# fig, ax = plt.subplots(figsize=(10,4))
# tips2 = pd.DataFrame(list(no_of_certs.items()), columns=['CA', 'Number'])
# print(tips2)
# # issuers_condensed = sns.load_dataset("tips2")
# sns.barplot(x="CA", y="Number", data=tips2, ax=ax)
# plt.show()

# pie chart
labels = sorted(no_of_certs, key=no_of_certs.get, reverse=True)
sizes = [no_of_certs[x] for x in sorted(no_of_certs, key=no_of_certs.get, reverse=True)]
sizes[9] = sum(sizes[9:])

labels[9] = "Others"

# Plot
plt.pie(sizes[:10], labels=labels[:10],
        autopct='%1.1f%%', shadow=True, startangle=140)

plt.axis('equal')
plt.show()
