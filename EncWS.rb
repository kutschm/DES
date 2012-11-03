#**********************************************************************
# 
# Data Encryption Service
#
#Include require gems\libs
require 'rubygems'
require 'sinatra'
require 'mongo'
require 'mongoid'
require 'haml'
require 'json'
require 'rest_client'
require 'digest'
require 'encryptor'
require 'base64'
require "sinatra/streaming" # from Sinatra-contrib

set :run, true
set :server, %w[webrick thin mongrel]
set :port, 4500

rcOK  =  200
rcERR =  400 

#**********************************************************************
#Model Classes

# This is a encrypted data store model
class Blobs
  include Mongoid::Document
  #field :dataId, :type => String
  field :blob,   :type => String

  #Validate
  #validates_uniqueness_of :dataId
  
end

#**********************************************************************
#Configure MongoDB block
configure do

	Mongoid.load!("./config/mongoid.yml", :development)

end


#**********************************************************************
#Helper functions
helpers do
  def encryptBlob blob, passPhrase   		
	## TODO put encryption logic
	puts "encrypting: " + blob + " using passphrase: " + passPhrase
	
	secret_key = Digest::SHA256.hexdigest(passPhrase)
	encrypted_value = Encryptor.encrypt(blob, :key => secret_key)
		
	Base64::encode64( encrypted_value )
  end
  
  def decryptBlob blob, passPhrase   		
	## TODO put encryption logic
	puts "decrypting: " + blob + " using passphrase: " + passPhrase

    encrypted_text = Base64::decode64(blob)

    secret_key = Digest::SHA256.hexdigest(passPhrase)
    decrypted_value = Encryptor.decrypt(encrypted_text, :key => secret_key)

	decrypted_value
  end


  def validateInput blob, regex
    
    ## TODO put validation logic
    puts "validating: " + blob + " using regex: " + regex
    
    true
  end
  
  def document_by_id id
    Blobs.find_by(:_id => id).to_json
  end
  
  def object_id_from_string val
    Moped::BSON::ObjectId.from_string(val)
  end

  def object_id_from_stringGridFs val
    BSON::ObjectId.from_string(val)
  end


end



#**********************************************************************
#Navigation Routes - TODO - this may need to change for intgretion
#Index page
get '/' do
  haml :index
end


#**********************************************************************
#    blob/store
#
# Allow a consumer to encrypt sensitive data 
# and store in the secure data store system
#
post '/blob/store/?' do  
  
  content_type :json
  
  # get the parameters
  jdataArray = JSON.parse(params[:data])
  puts jdataArray
  
  returnArray = Array.[]
  
  jdataArray.each { |jdata|
	if validateInput(jdata['blob'], jdata['validationRegex'] )
		puts "Input validated successfully\n"
	
		# encrypt the data
		encBlob = encryptBlob(jdata['blob'], jdata['passPhrase'] )

		# write to mongodb
		#TODO create a uuid
		puts "Insert data into mongodb " + encBlob
		blob = Blobs.new(blob: encBlob)
		blob.save(validate: false)
		
		blobId = blob[:_id].to_s
		puts "Inserted with id " + blobId
		
		returnJson = { :storageKey    => blobId,
					   :returnCode    => rcOK,
                       :returnMessage => ""
                     }
        returnArray << returnJson
	end
  }
  
  # create return json object
  returnArray.to_json
end

#**********************************************************************
#    blob/read
#
# Allow a consumer to retrieve records from the encrypted data store 
# individually the web service returns them 
# decrypted in plain text UTF8 back to the user.
#
post '/blob/read' do
  content_type :json
  
  # get the parameters
  jdataArray = JSON.parse(params[:data])
  puts jdataArray
  
  returnArray = Array.[]
  
  jdataArray.each { |jdata|
	  # extract row from data store
	  puts "id " + jdata['storageKey']
	  doc = JSON.parse(document_by_id( object_id_from_string( jdata['storageKey'] ) ))
	  puts doc
	  # decrypt the data
	  decBlob = decryptBlob(doc['blob'], jdata['passPhrase'] )

	  returnJson = { :storageKey    => jdata['storageKey'],
					 :blob          => decBlob,
					 :returnCode    => rcOK,
					 :returnMessage => ""
				   }				   
      returnArray << returnJson
   }

  returnArray.to_json
end


#**********************************************************************
#    blob/retrieve
#
# Allow a consumer to encrypt sensitive data 
# and retrieve the encrypted data without storing it in the system
#
post '/blob/retrieve/?' do  
  
  content_type :json
  
  # get the parameters
  jdataArray = JSON.parse(params[:data])
  puts jdataArray
  
  returnArray = Array.[]
  
  jdataArray.each { |jdata|
	  if validateInput(jdata['blob'], jdata['validationRegex'] )
		puts "Input validated successfully\n"
		
		# encrypt the data
		encBlob = encryptBlob(jdata['blob'], jdata['passPhrase'] )

	  end  
	  # create return json object
	  returnJson = { :encryptedBlob => encBlob,
					 :returnCode    => rcOK,
					 :returnMessage => ""
				   }
      returnArray << returnJson
   }

  returnArray.to_json
end



#**********************************************************************
#    blob/send
#
# Allow a consumer to send an encrypted text to the server
# and getting the decrypted text back. This does not involve
# storing or reading from the data store.
#
post '/blob/send/?' do
  content_type :json
  
  jdataArray = JSON.parse(params[:data])
  puts jdataArray
  
  returnArray = Array.[]
  
  jdataArray.each { |jdata|
	  # decrypt the data
	  decBlob = decryptBlob(jdata['encryptedBlob'], jdata['passPhrase'] )

	  returnJson = { :blob          => decBlob,
					 :returnCode    => rcOK,
					 :returnMessage => ""
				   }
      returnArray << returnJson
   }

  returnArray.to_json
end


# curl -G -d "id=50954b577506a463eb000031"  http://localhost:4500/stream
get '/stream/?' do
  puts params[:id]
  stream do |out|
  db = Mongo::Connection.new.db("mydb")
  grid = Mongo::Grid.new(db)
  # Retrieve the file
  id = object_id_from_stringGridFs( params[:id] )
  file = grid.get( id )
  out << file.read()
  #file.each {|chunk| out << chunk  }
  end

end


# curl -v --location --upload-file d.bin http://localhost:4500/upload
put '/upload/:id' do
	db = Mongo::Connection.new.db("mydb")
	grid = Mongo::Grid.new(db)	
	id = grid.put(request.body.read)
end
