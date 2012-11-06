require 'rubygems'
require 'rest_client'
require 'active_support/core_ext'
require 'json'


mainUrl = "http://localhost:4500"

##########################################################
#                   post blob/store
##########################################################
dataArray = Array.[]
#first element
data = { :passPhrase      => "phrase1",
         :blob		 	  => "text to encrypt1",
         :validationRegex => "foo" }
dataArray << data
# second element
data = { :passPhrase      => "phrase2",
         :blob		 	  => "text to encrypt12",
         :validationRegex => "foo" }
dataArray << data
dataArray = dataArray.to_json
         
puts "POST blob/store " + dataArray.to_s
response = RestClient.post mainUrl + "/blob/store", 
                           { :data => dataArray }, # post array
                           { :content_type => :json, :accept => :json }
                           
puts "\n!!!!!!!/blob/store RESULT!!!!!!! \n"                           
JSON.parse(response).each { |data| 
	puts "\nRespose object: \n"
	puts "StorageKey: " + data['storageKey']
	puts "ReturnCode: " + data['returnCode'].to_s
	puts "ReturnMessage: " + data['returnMessage'].to_s
}
puts "\n!!!!!!!/blob/store RESULT!!!!!!! \n"                           

##########################################################
#                   post blob/read/:id
##########################################################
# first element
data1 = { :passPhrase       => JSON.parse(dataArray)[0]['passPhrase'],
          :storageKey       => JSON.parse(response)[0]['storageKey']
        }

# second element
data2 = { :passPhrase       => JSON.parse(dataArray)[1]['passPhrase'],
          :storageKey	    => JSON.parse(response)[1]['storageKey']
        }
dataArray = []
dataArray << data1
dataArray << data2
dataArray = dataArray.to_json

         
puts "POST blob/read " + dataArray.to_s
response = []
response = RestClient.post mainUrl + "/blob/read", 
                           { :data => dataArray }, # post array
                           { :content_type => :json, :accept => :json }

puts "\n!!!!!!!/blob/read RESULT!!!!!!! \n"                           
JSON.parse(response).each { |data| 
	puts "\nRespose object: \n"
	puts "StorageKey: " + data['storageKey']
	puts "Blob: " + data['blob']
	puts "ReturnCode: " + data['returnCode'].to_s
	puts "ReturnMessage: " + data['returnMessage'].to_s
}
puts "\n!!!!!!!/blob/read RESULT!!!!!!! \n"                           

##########################################################
#                   post blob/retrieve
##########################################################
dataArray = Array.[]
data1 = { :passPhrase      => "phrase1",
          :blob		 	   => "text to encrypt1",
          :validationRegex => "foo" }

data2 = { :passPhrase      => "phrase2",
          :blob		 	   => "another text to encrypt",
          :validationRegex => "foo" }

dataArray << data1
dataArray << data2
dataArray = dataArray.to_json
         
puts "POST blob/retrieve " + dataArray.to_s
response = RestClient.post mainUrl + "/blob/retrieve", 
                           { :data => dataArray },
                           { :content_type => :json, :accept => :json }

puts "\n!!!!!!!/blob/retrieve RESULT!!!!!!! \n"                           
JSON.parse(response).each { |data| 
	puts "\nRespose object: \n"
	puts "EncryptedBlob: " + data['encryptedBlob']
	puts "ReturnCode: " + data['returnCode'].to_s
	puts "ReturnMessage: " + data['returnMessage'].to_s
}
puts "\n!!!!!!!/blob/retrieve RESULT!!!!!!! \n"                           

##########################################################
#                   post blob/send
##########################################################
# first element
data1 = { :passPhrase       => JSON.parse(dataArray)[0]['passPhrase'],
          :encryptedBlob    => JSON.parse(response)[0]['encryptedBlob']
        }

# second element
data2 = { :passPhrase       => JSON.parse(dataArray)[1]['passPhrase'],
          :encryptedBlob	=> JSON.parse(response)[1]['encryptedBlob']
        }

dataArray = []
dataArray << data1
dataArray << data2
dataArray = dataArray.to_json

         
puts "POST blob/send " + dataArray.to_s
response = RestClient.post mainUrl + "/blob/send", 
                           { :data => dataArray },
                           { :content_type => :json, :accept => :json }

puts "\n!!!!!!!/blob/send RESULT!!!!!!! \n"                           
JSON.parse(response).each { |data| 
	puts "\nRespose object: \n"
	puts "Blob: " + data['blob']
	puts "ReturnCode: " + data['returnCode'].to_s
	puts "ReturnMessage: " + data['returnMessage'].to_s
}
puts "\n!!!!!!!/blob/send RESULT!!!!!!! \n"                           


#### testing streaming GridIO #######


puts "\n!!!!!!!Uploading file!!!!!!! \n" 
response = RestClient.put mainUrl + '/upload', :myfile => File.new("lorem.txt", 'rb')
puts response
puts "\n!!!!!!!Downloading file!!!!!!! \n" 
response = RestClient.get mainUrl + '/stream?id=' + response
file = File.open("retrievedFile.md", "w")
file.write(response) 
#puts "Respose: " + response



puts "\n!!!!!!!Uploading file CHUNKS!!!!!!! \n" 
response = RestClient.put mainUrl + '/upload2', :myfile => File.new("lorem.txt", 'rb')
puts response
puts "\n!!!!!!!Downloading file!!!!!!! \n" 
response = RestClient.post mainUrl + '/stream2',
							{:data => response}
							
file = File.open("retrievedLorem.txt", "w")
file.write(response) 
