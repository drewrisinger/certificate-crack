import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from functools import reduce

no_of_certs = dict()

with open('subject.txt', 'r') as f:
    for name in f.readlines():
        name = name.rstrip("\n\r")
        ca_certs_list = name.split(": ")
        # ca_certs_list[0] = ca_certs_list[0].split(" ")[0]
        # # some custom fixes
        if ca_certs_list[0] == "Thawte Consulting (Pty) Ltd":
            ca_certs_list[0] = "Thawte, Inc."
        elif ca_certs_list[0] == "thawte, Inc.":
            ca_certs_list[0] = "Thawte, Inc."
        # elif ca_certs_list[0] == "thawte,":
        #     ca_certs_list[0] = "Thawte"

        if (ca_certs_list[0] in no_of_certs) and (len(ca_certs_list) > 1):
            no_of_certs[ca_certs_list[0]] += int(ca_certs_list[1])
        elif len(ca_certs_list) > 1:
            no_of_certs[ca_certs_list[0]] = int(ca_certs_list[1])

for key in sorted(no_of_certs, key=no_of_certs.get, reverse=True):
    print("Organization: {0}, No of issues: {1}".format(key, no_of_certs[key]))

with open('subjects_condensed.csv', 'w') as f:
    # f.write("CA, No_of_certs_issued\n")
    for key in sorted(no_of_certs, key=no_of_certs.get, reverse=True):
        f.write(key + ", " + str(no_of_certs[key]) + "\n")

# list_certs = [(k, no_of_certs[k]) for k in sorted(no_of_certs, key=no_of_certs.get, reverse=True)]
# # Seaborn plot
# fig, ax = plt.subplots(figsize=(10,4))
# tips2 = pd.DataFrame(list_certs[:30], columns=['CA', 'Number'])
# print(tips2)
# # issuers_condensed = sns.load_dataset("tips2")
# sns.barplot(x="CA", y="Number", data=tips2, ax=ax)
# plt.tight_layout()
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

labels = sorted(no_of_certs, key=no_of_certs.get, reverse=True)
sizes = [no_of_certs[x] for x in sorted(no_of_certs, key=no_of_certs.get, reverse=True)]
sizes[29] = sum(sizes[29:])

labels[29] = "Others"

# Plot
plt.pie(sizes[18:30], labels=labels[18:30],
        autopct='%1.1f%%', shadow=True, startangle=140)

plt.axis('equal')
plt.show()
