require 'rubygems'
require 'rest_client'
require 'active_support/core_ext'
require 'json'


mainUrl = "http://localhost:4500"

##########################################################
#                   post blob/store
##########################################################
data = { :passPhrase      => "phrase",
         :blob		 	  => "text to encrypt",
         :validationRegex => "foo" }.to_json
         
puts "POST blob/store " + data
response = RestClient.post mainUrl + "/blob/store", 
                           { :data => data },
                           { :content_type => :json, :accept => :json }
puts "Result: " + response
puts "done... blob/store\n\n"

##########################################################
#                   get blob/read/:id
##########################################################
data = { :passPhrase       => JSON.parse(data)['passPhrase'],
          :storageKey	   => JSON.parse(response)['storageKey']
        }.to_json
         
puts "POST blob/read " + data
response = RestClient.post mainUrl + "/blob/read", 
                           { :data => data },
                           { :content_type => :json, :accept => :json }
puts "Result: " + response
puts "done... blob/read\n\n"


##########################################################
#                   post blob/retrieve
##########################################################
data = { :passPhrase      => "phrase",
         :blob		 	  => "text to encrypt",
         :validationRegex => "foo" }.to_json
         
puts "POST blob/retrieve " + data
response = RestClient.post mainUrl + "/blob/retrieve", 
                           { :data => data },
                           { :content_type => :json, :accept => :json }
puts "Result: " + response
puts "done... blob/retrieve\n\n"


##########################################################
#                   post blob/send
##########################################################
data = { :passPhrase      => JSON.parse(data)['passPhrase'],
         :encryptedBlob	  => JSON.parse(response)['encryptedBlob']
       }.to_json
         
puts "POST blob/send " + data
response = RestClient.post mainUrl + "/blob/send", 
                           { :data => data },
                           { :content_type => :json, :accept => :json }
puts "Result: " + response
puts "done... blob/send\n\n"
