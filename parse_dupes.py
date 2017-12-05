import csv

datafile = open('dupes.txt', 'r')
datareader = csv.reader(datafile, delimiter=';')
data = []
for row in datareader:
    data.append(row)

data_processed = list();

for row in data:
    i = 0;
    for el in row:
        el = el.split(' ')[0]
        print(el)
        i += 1;
    row = list(filter(None, row))
    # print(data_processed)
