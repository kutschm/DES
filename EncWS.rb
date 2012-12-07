#**********************************************************************
# 
# Data Encryption Service
#
#Include require gems\libs
require 'rubygems'
require 'sinatra'
require 'mongo'
require 'mongo_mapper'
require 'haml'
require 'json'
require 'rest_client'
require 'digest'
require 'encryptor'
require 'base64'
require "sinatra/streaming" # from Sinatra-contrib
#require 'Haml'

#set :run, true
#set :server, %w[thin mongrel webrick]
#set :port, 4500

rcOK  =  200
rcERR =  400 

#**********************************************************************
#Model Classes

# This is a encrypted data store model
class Blobs
  include MongoMapper::Document
  #field :dataId, :type => String
  key :blob, String

  #Validate
  #validates_uniqueness_of :dataId
  
end

    MongoMapper.connection = Mongo::Connection.new('localhost', 27017)
    MongoMapper.database = "encws"

#**********************************************************************
#Configure MongoDB block
#configure do

#	Mongoid.load!("./config/mongoid.yml", :development)

#end


#**********************************************************************
#Helper functions
helpers do
  def encryptBlob blob, passPhrase   	
	## TODO put encryption logic
	#puts "encrypting: " + blob + " using passphrase: " + passPhrase
	
	secret_key = Digest::SHA256.hexdigest(passPhrase)
	encrypted_value = Encryptor.encrypt(blob, :key => secret_key)
		
	Base64::encode64( encrypted_value )	
  end
  
  def decryptBlob blob, passPhrase   		
	## TODO put encryption logic
	#puts "decrypting: " + blob + " using passphrase: " + passPhrase

    encrypted_text = Base64::decode64(blob)   

    secret_key = Digest::SHA256.hexdigest(passPhrase)
    decrypted_value = Encryptor.decrypt(encrypted_text, :key => secret_key)

	decrypted_value
  end

  def encryptBlobNB64 blob, passPhrase   		
	## TODO put encryption logic
	#puts "encrypting: " + blob + " using passphrase: " + passPhrase
	
	secret_key = Digest::SHA256.hexdigest(passPhrase)
	encrypted_value = Encryptor.encrypt(blob, :key => secret_key)
		
	encrypted_value
  end
  
  def decryptBlobNB64 blob, passPhrase   		
	## TODO put encryption logic
	#puts "decrypting: " + blob + " using passphrase: " + passPhrase

    encrypted_text = blob

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
    Blobs.where(:_id => id).first.to_json
  end
  
  def object_id_from_string val
    BSON::ObjectId.from_string(val)
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

get '/about' do  
  haml :about  
end 

get '/store' do  
  haml :store
end 

get '/otf' do  
  haml :otf  
end 

get '/file' do  
  haml :file
end 

get '/createlink' do
  haml :createlink
end

get '/getlink/:link' do|link|
  @link = link
  haml :getlink
  #haml :getlink, :locals => { :link => link }
end

post '/showlink' do
  @link = params["link"]
  @phrase = params["phrase"]
  haml :showlink
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
  puts(params)
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
post '/blob/read/?' do
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
  puts "streaming data back"
  puts params[:id]
  stream do |out|
  db = Mongo::Connection.new.db("mydb")
  grid = Mongo::Grid.new(db)
  # Retrieve the file
  id = object_id_from_stringGridFs( params[:id] )
  file = grid.get( id )  
  
  #file.each {|chunk| 
  #decBlob = decryptBlob(chunk, 'passPhrase' ) }
  
  decBlob = decryptBlob(file.read(), 'passPhrase' )
  
  out << decBlob
  end

end


# curl -v --location --upload-file d.bin http://localhost:4500/upload
put '/upload/?' do
puts params
	db = Mongo::Connection.new.db("mydb")
	grid = Mongo::Grid.new(db)	
	
	puts "encrypt data"
	encBlob = encryptBlob(params['myfile'][:tempfile].read, 'passPhrase' )
	id = grid.put(encBlob)	
	id.to_s
end


################# CHUNKED encryption

CHUNKSIZE = 300000

class File
  def each_chunk(chunk_size = CHUNKSIZE)
    yield read(chunk_size) until eof?
  end
end

# curl -v --location --upload-file d.bin http://localhost:4500/upload
put '/upload2/?' do
puts "upload chunks"
puts params
	db = Mongo::Connection.new.db("mydb")
	grid = Mongo::Grid.new(db)	
	
	id = []
	
	puts "encrypt data"
	open(params['myfile'][:tempfile], "rb") do |f|
		f.each_chunk() {|chunk| 
			puts "Processing chunk upload"
			puts chunk.size
			encBlob = encryptBlob(chunk, 'passPhrase' ) 
			puts encBlob.size
			id << grid.put(encBlob)	}
			puts id
	end
	id.to_json
end


post '/stream2/?', provides: 'text/event-stream' do

  #content_type :json
  #content_type 'text/event-stream'
	
  puts "streaming data back chunks"
  jdata = JSON.parse(params[:data])  
  
  stream do |out|
  db = Mongo::Connection.new.db("mydb")
  grid = Mongo::Grid.new(db)
  # Retrieve the file
  jdata.each { |x|     
	  id = object_id_from_stringGridFs( x['$oid'] )
	  file = grid.get( id )  
	  
	  decBlob = decryptBlob(file.read(), 'passPhrase' )
	  #file.each {|chunk| 
	   #puts "Processing chunk stream"
	   #puts chunk.size
	   #decBlob = decryptBlobNB64(chunk, 'passPhrase' )
	   out << decBlob
  }
  
  #decBlob = decryptBlob(file.read(), 'passPhrase' )      
  end

end


post '/file/?' do
puts "upload chunks"
puts params
	db = Mongo::Connection.new.db("mydb")
	grid = Mongo::Grid.new(db)	
	
	id = []
	
	puts "encrypt data"
	open(params['myfile'][:tempfile], "rb") do |f|
		f.each_chunk() {|chunk| 
			puts "Processing chunk upload"
			puts chunk.size
			encBlob = encryptBlob(chunk, 'passPhrase' ) 
			puts encBlob.size
			id << grid.put(encBlob)	}
			puts id
	end
	id.to_json
end
