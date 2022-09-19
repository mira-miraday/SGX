
import os
import operator
import csv,pickle
import random
import operator

class StreamingAnalyser:
    def __init__(self,freqFile,dirFolder, outDirFolder, threshold):
        self.csvfile = freqFile
        self.dirPath = os.path.join(os.getcwd(),dirFolder); ## 输入文件目录
        self.outPath = outDirFolder  ## 输出文件目录
        self.threshold = threshold
        self.keyword_id_map = dict() ## 关键字和id的映射
        self.keyword_id_count = 0 ## 关键字个数

    def retrieve_keywords_from_files(self,fileId):
        fp = open(os.path.join(self.dirPath,str(fileId)))
        data = fp.read()
        keywords = data.split(",")
        # self.word_id_count = self.word_id_count + len(keywords)
        fp.close()
        return keywords
    
    def processCSV(self):
        lineNum = 0
        with open(self.csvfile) as f:    
            reader = csv.reader(f)
            for row in reader:
                # print(row)
                lineNum += 1
                if '\n' not in row[0]: 
                    self.keyword_id_map[row[0]] = str(self.keyword_id_count)
                    self.keyword_id_count += 1    
        print(self.keyword_id_count)

    #function samples streaming data set by using the constructed and inverted index
    def dump_freq_by_threshold(self):
         
        for fileId in range(1,self.threshold+1):
            keyword_set = self.retrieve_keywords_from_files(fileId)
            line = ""
            for keyword in keyword_set:
                if keyword not in self.keyword_id_map:
                    print(fileId)
                else:
                    line += str(self.keyword_id_map[keyword])
                    line += ","
            line =line[:-1]
            # print(line)
            with open(os.path.join(outDirFolder, str(fileId)), "a+") as myfile:
                myfile.write(line)



        #dump frequencies to file
        # with open('freq' + str(self.threshold) + '.csv', 'w') as csv_file:
        #     writer = csv.writer(csv_file)
        #     for w in sorted(self.freq, key=self.freq.get, reverse=True):
        #         writer.writerow([w, self.freq[w]])

        print("Completed")


if __name__ == '__main__':
    dirFolder="../streaming"
    freqFile="freq100000.csv"
    outDirFolder="../rangeStreaming"
    threshold = 10
    app = StreamingAnalyser(freqFile,dirFolder, outDirFolder, threshold) #threshold=100000
    app.processCSV()
    app.dump_freq_by_threshold()
    print('Total file generated:', threshold)
    print('Max keyword:', app.keyword_id_count)
    # print('Total (w,in) count:', app.word_id_count)