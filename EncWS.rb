#**********************************************************************
# 
# Data Encryption Service
#
#Include require gems\libs
require 'rubygems'
require 'sinatra'
require 'mongoid'
require 'haml'
require 'json'
require 'rest_client'
require 'digest'
require 'encryptor'
require 'base64'


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
  
  def object_id val
    Moped::BSON::ObjectId.from_string(val)
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
  jdata = JSON.parse(params[:data])
  puts jdata
  
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
  end  
  
  # create return json object
  returnJson = { :storageKey    => blobId,
                 :returnCode    => rcOK,
                 :returnMessage => ""
               }.to_json
  
  returnJson
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
  jdata = JSON.parse(params[:data])
  puts jdata
  	
  # extract row from data store
  puts "id " + jdata['storageKey']
  doc = JSON.parse(document_by_id( object_id( jdata['storageKey'] ) ))
  puts doc
  # decrypt the data
  decBlob = decryptBlob(doc['blob'], jdata['passPhrase'] )

  returnJson = { :storageKey    => jdata['storageKey'],
				 :blob          => decBlob,
                 :returnCode    => rcOK,
                 :returnMessage => ""
               }.to_json

  returnJson
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
  jdata = JSON.parse(params[:data])
  puts jdata
  
  if validateInput(jdata['blob'], jdata['validationRegex'] )
    puts "Input validated successfully\n"
	
	# encrypt the data
	encBlob = encryptBlob(jdata['blob'], jdata['passPhrase'] )

  end  
  
  # create return json object
  returnJson = { :encryptedBlob => encBlob,
                 :returnCode    => rcOK,
                 :returnMessage => ""
               }.to_json
  
  returnJson
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
  
  # get the parameters
  jdata = JSON.parse(params[:data])
  puts jdata
  	
  # decrypt the data
  decBlob = decryptBlob(jdata['encryptedBlob'], jdata['passPhrase'] )

  returnJson = { :blob          => decBlob,
                 :returnCode    => rcOK,
                 :returnMessage => ""
               }.to_json

  returnJson
end
