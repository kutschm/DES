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
require "uuid"
require "#{File.dirname(__FILE__)}/pool"
require "#{File.dirname(__FILE__)}/channel"
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

class BlobsToSingleId
  include MongoMapper::Document
  key :uid, String
  key :order, Integer
  key :blodId, String
  
end

    MongoMapper.connection = Mongo::Connection.new('localhost', 27017)
    MongoMapper.database = "encws"

class ReturnWrapper
   @rcOK = 200
   @rcERR = 400
   def initialize(value, error, msg)
      @decryptValue=value
      @error=error
      @errorMessage=msg
   end
   
   def getError
     @error
   end
   
   def getValue
     @decryptValue
   end
   
   def getMessage
     @errorMessage
   end
end

class ChunkWrapper
   def initialize(chunk, id)
      @chunk=chunk
      @id=id
   end
   
   def getChunk
     @chunk
   end
   
   def getId
     @id
   end
   
end

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
    if(encrypted_text == "")
      return ReturnWrapper.new(nil, 400, "Incomplete encrypted data");
    end
    secret_key = Digest::SHA256.hexdigest(passPhrase)
    decrypted_value = Encryptor.decrypt(encrypted_text, :key => secret_key)
    decryptValue = ReturnWrapper.new(decrypted_value, 200, "");    
    rescue OpenSSL::Cipher::CipherError => e
      decryptValue = ReturnWrapper.new(decrypted_value, 400, "Invalid Password");

	decryptValue
  end


  def validateInput blob, regex
    
    regexp = Regexp.new(regex);
    (regexp.match(blob))? true : false;
        
  end
  
  def document_by_id id
    Blobs.where(:_id => id).first            
  end
  
  def object_id_from_string val
    oid = BSON::ObjectId.from_string(val)
    id = ReturnWrapper.new(oid, 200 , "");
    rescue BSON::InvalidObjectId => e
        id = ReturnWrapper.new(nil, 400, "Invalid StorageKey");
    id
  end
  
  def object_id_from_stringGridFs val
    oid = BSON::ObjectId.from_string(val)
    id = ReturnWrapper.new(oid, 200, "");
    rescue BSON::InvalidObjectId => e
      id = ReturnWrapper.new(nil, 400, "Invalid StorageKey");
    
    id
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
  
  retCode = rcOK
  retMsg = ""
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

		retCode = rcOK;		
		retMsg  = "Encrypted Data stored successfully";
    else        
		retCode = rcERR;
		retMsg  = "Input validation failed for provided regex."
	end

	returnJson = { :storageKey    => blobId,
				   :returnCode    => retCode,
				   :returnMessage => retMsg
				 }
	returnArray << returnJson	
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
  
  retCode = rcOK
  retMsg = ""
  # get the parameters
  jdataArray = JSON.parse(params[:data])
  puts jdataArray
  
  returnArray = Array.[]
  
  jdataArray.each { |jdata|
	  # extract row from data store
	  puts "id " + jdata['storageKey']

	  obj = object_id_from_string( jdata['storageKey'] )
	  if ( obj.getError() == 200 )	  
	    doc = document_by_id( obj.getValue() )
	    if (doc != nil)	      
	      doc = JSON.parse(doc.to_json)
	      puts doc
	      # decrypt the data
	      obj = decryptBlob(doc['blob'], jdata['passPhrase'] )      
	    else
	      obj = ReturnWrapper.new(nil, 400, "Document does not exist")
	    end
      end	  
      
	  returnJson = { :storageKey    => jdata['storageKey'],
					 :blob          => obj.getValue(),
					 :returnCode    => obj.getError(),
					 :returnMessage => obj.getMessage()
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
  
  retCode = rcOK
  retMsg = ""
  # get the parameters
  jdataArray = JSON.parse(params[:data])
  puts jdataArray
  
  returnArray = Array.[]
  
  jdataArray.each { |jdata|
	  if validateInput(jdata['blob'], jdata['validationRegex'] )
		puts "Input validated successfully\n"

		# encrypt the data
		encBlob = encryptBlob(jdata['blob'], jdata['passPhrase'] )

		retCode = rcOK;		
		retMsg  = "Data encrypted successfully";
	  else        
		retCode = rcERR;
		retMsg  = "Input validation failed for provided regex."
	  end

	  # create return json object
	returnJson = { :encryptedBlob    => encBlob,
				   :returnCode    => retCode,
				   :returnMessage => retMsg
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

	  returnJson = { :blob          => decBlob.getValue,
					 :returnCode    => decBlob.getError(),
					 :returnMessage => decBlob.getMessage()
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

CHUNKSIZE = 300

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


post '/file2/?' do
puts "upload chunks"
puts params
	db = Mongo::Connection.new.db("mydb")
	grid = Mongo::Grid.new(db)		

	retCode = rcOK
    retMsg = ""

	id = 0
	enum = 0
	blobsToId = nil
	uuid = UUID.new
	uuid = uuid.generate.to_s
	puts uuid
	returnArray = Array.[]

	puts "encrypt data"
	open(params['myfile'][:tempfile], "rb") do |f|
		f.each_chunk() {|chunk|
			puts "Processing chunk upload"
			#puts chunk.size
			encBlob = encryptBlob(chunk, params['passPhrase'] )
			#puts encBlob.size
			id = grid.put(encBlob)
			id = id.to_s
			blobsToId = BlobsToSingleId.new(uid: uuid, order: enum, blobId: id)
			blobsToId.save(validate: false)
			puts "saving: " + uuid + " " + enum.to_s + " " + id
			enum += 1   
    }
	end
    returnJson = { :storageKey    => uuid,
	   		       :returnCode    => retCode,
				   :returnMessage => retMsg
				 }
    returnArray << returnJson

    returnArray.to_json
end


post '/file3/?' do
puts "upload chunks"
puts params

	retCode = rcOK
    retMsg = ""

	id = 0
	enum = 0
	blobsToId = nil
	uuid = UUID.new
	uuid = uuid.generate.to_s
	puts uuid
	returnArray = Array.[]
    pool = Thread::Pool.new(5)
	channel = Thread::Channel.new { |o| o}

		   a = Thread.new {
				while true
				  puts "checking queue"
				  chunkItem = channel.receive()
				  puts "received " + chunkItem.getId().to_s
				  if (chunkItem.getId() == -1)
				     puts "over"
				     break
				  else
                    puts "Use pool" 
					pool.process() {
					    myChunkItem = chunkItem.clone()
						db = Mongo::Connection.new.db("mydb")
						grid = Mongo::Grid.new(db)		
					  
						puts "Processing chunk upload "
						#puts chunk.size
						encBlob = encryptBlob(myChunkItem.getChunk(), params['passPhrase'] )
						puts encBlob.size
						id = grid.put(encBlob)
						id = id.to_s
						blobsToId = BlobsToSingleId.new(uid: uuid, order: myChunkItem.getId(), blobId: id)
						puts "saving to mongo"						
						blobsToId.save(validate: false)						
						puts "saving: " + uuid + " " + myChunkItem.getId().to_s + " " + id
					}					                 
                  end
                end                 
                
                puts "ending " + pool.backlog.to_s
                #pool.join
                while(pool.backlog != 0)
					puts "pool not empty" + pool.backlog.to_s					
					sleep 0.5
				end
				puts "shutting down pool"
                pool.shutdown
		   }
		   a.run

	puts "encrypt data"	
	open(params['myfile'][:tempfile], "rb") do |f|	
		f.each_chunk() {|chunk|		
		   chunkW = ChunkWrapper.new(chunk, enum);
		   channel.send chunkW		   
		   enum += 1   
        }
        sleep 2
        puts "sending -1"
        chunkW = ChunkWrapper.new(nil, -1);               
        channel.send chunkW		   
        
        a.join
		
	end
    returnJson = { :storageKey    => uuid,
	   		       :returnCode    => retCode,
				   :returnMessage => retMsg
				 }
    returnArray << returnJson

    returnArray.to_json
end


post '/stream3/?', provides: 'text/event-stream' do

  jdata = JSON.parse(params[:data])  
  puts "streaming data back chunks " + jdata.to_s
  
  stream do |out|
  db = Mongo::Connection.new.db("mydb")
  grid = Mongo::Grid.new(db)
  
  # Retrieve the file
  jdata.each { |x| 
      puts "ID " + x['$oid'].to_s
      ids = BlobsToSingleId.where(:uid => x['$oid'].to_s ).sort(:order.asc)
      ids.each { |y|
        puts ids
        
	    id = object_id_from_stringGridFs( y['blobId'] )
	    file = grid.get( id.getValue() )

	    decBlob = decryptBlob(file.read(), x['passPhrase'] ) 
	  #file.each {|chunk| 
	   #puts "Processing chunk stream"
	   #puts chunk.size
	   #decBlob = decryptBlobNB64(chunk, 'passPhrase' )
	   if(decBlob.getError() == 200)
	    puts "successful"
		out << decBlob.getValue()
	   else
	     out << "storageKey: " + decBlob.getValue().to_s + 
	   		    "returnCode: " + decBlob.getError().to_s + 
				"returnMessage: " + decBlob.getMessage()     				     
	   end
	}
  }
  
  #decBlob = decryptBlob(file.read(), 'passPhrase' )      
  end

end


post '/file4/?' do
puts "upload chunks"
puts params

	retCode = rcOK
    retMsg = ""

    mutex = Mutex.new
	id = 0
	enum = 0
	blobsToId = nil
	uuid = UUID.new
	uuid = uuid.generate.to_s
	puts uuid
	returnArray = Array.[]
    pool = Thread::Pool.new(5)
	channel = Thread::Channel.new { |o| o}

	5.times {
		pool.process() {
		  puts "starting process"
		  while true do
		      mutex.synchronize {
  			    chunkItem = channel.receive()
			   # myChunkItem = chunkItem.clone()
			  }
			  puts "got chunk" + chunkItem.getId().to_s
				if (myChunkItem.getId() > -1)					
					db = Mongo::Connection.new.db("mydb")
					grid = Mongo::Grid.new(db)		
				  
					#puts chunk.size
					encBlob = encryptBlob(chunkItem.getChunk(), params['passPhrase'] )
					#puts encBlob.size
					id = grid.put(encBlob)
					id = id.to_s
					blobsToId = BlobsToSingleId.new(uid: uuid, order: chunkItem.getId(), blobId: id)
					blobsToId.save(validate: false)						
					puts "saving: " + uuid + " " + chunkItem.getId().to_s + " " + id
				else
					chunkW = ChunkWrapper.new(nil, -1);               
					channel.send chunkW		   
					puts "ending process"
					break;
				end
			  end			  
			 }
		}					                	 
	
	puts "encrypt data"	
	open(params['myfile'][:tempfile], "rb") do |f|	
		f.each_chunk() {|chunk|		
		   myChunk = chunk.clone()
		   chunkW = ChunkWrapper.new(myChunk, enum);
		   channel.send chunkW		   
		   enum += 1   
        }
        sleep 5
#        puts "sending -1"
        chunkW = ChunkWrapper.new(nil, -1);               
        #channel.send chunkW		   
        
	    while(pool.backlog > 0)	
	       sleep 0.5
	    end
	    
	    #pool.shutdown
	end
	
    returnJson = { :storageKey    => uuid,
	   		       :returnCode    => retCode,
				   :returnMessage => retMsg
				 }
    returnArray << returnJson

    returnArray.to_json
end
