# Copyright (c) 2006 Stuart Eccles
# Released under the MIT License.  See the LICENSE file for more details.

# The FileWebDavResource represents a WebDavResource representing a filesystem files and directories
# It exposes a set of properties that are central to representing to a WebDAV client as a file system
# These are displayname, creationdate, getlastmodified, getetag, getcontenttype and getcontentlength
# The FileWebDavResource allows for setting of the displayname and last modified dates.

require 'mime/types'

class ActiveRecordWebDavResource

  include WebDavResource
  attr_accessor :ar, :href
   
  WEBDAV_PROPERTIES = [:displayname, :creationdate, :getlastmodified, :getetag, :getcontenttype, :getcontentlength]
   
  #First argument should be an ActiveRecord
  # # , with then an absolute href to the file. The href is returned with the propfind
  def initialize(ar, href)
    @ar   = ar
    @href = href; # + ar.path
    @href = @href + '/' if collection?
    # Damn! need to pass "/ardav" in somehow.
    # get it from the path info?
    #@href = "/ardav" + @href
  end
   
  def collection?
    unless @ar.nil?
      @ar.is_directory
    end
  end
   
  def delete!
    @ar.delete
=begin
     begin
       FileUtils.rm_rf(@file)
     rescue Errno::EPERM
        raise WebDavErrors::ForbiddenError
     end
=end
  end
   
  def move! (dest_path, depth)
    begin
      @ar.path = dest_path
      @ar.save!
    rescue Errno::ENOENT
      #Conflict
      raise WebDavErrors::ConflictError
    rescue Errno::EPERM
      #Forbidden
      raise WebDavErrors::ForbiddenError
    end
  end

  def copy! (ar, depth)
    begin
      # todo needs to cp -r
      ar.data = @ar.data
      ar.save
    rescue Errno::ENOENT
      #Conflict
      raise WebDavErrors::ConflictError
    rescue Errno::EPERM
      #Forbidden
      raise WebDavErrors::ForbiddenError
    end
  end
   
  def children
    return [] unless collection?
    resources = []
    @ar.children.each do |entry|
      Rails.logger.debug "Adding #{entry}, #{@href}, #{entry.name}"
      resources << ActiveRecordWebDavResource.new(entry, File.join(@href, entry.name))
    end
    return resources
  end
   
  def properties
    WEBDAV_PROPERTIES
  end 

  def displayname
    @ar.name
  end
   
  def set_displayname(value)
    begin
      @ar.name = value
      @ar.save!
      gen_status(200, "OK").to_s
    rescue Errno::EACCES, ArgumentError
      gen_status(409, "Conflict").to_s
    rescue
      gen_status(500, "Internal Server Error").to_s
    end 
  end
   
  def creationdate
    @ar.created_at.xmlschema unless @ar.nil?
  end
   
  def getlastmodified
    @ar.updated_at.httpdate unless @ar.nil?
  end
   
  def set_getlastmodified(value)
    begin
      @ar.updated_at = Time.httpdate(value)
      @ar.save!
      gen_status(200, "OK").to_s
    rescue Errno::EACCES, ArgumentError
      gen_status(409, "Conflict").to_s
    rescue
      gen_status(500, "Internal Server Error").to_s
    end
  end
   
  def getetag
    sprintf('%x-%x-%x', @ar.id, @ar.size, @ar.updated_at.to_i) unless @ar.nil?
  end
      
  def getcontenttype
    mimetype = MIME::Types.type_for(displayname).first.to_s
    mimetype = "application/octet-stream" if mimetype.blank?
    collection? ? "httpd/unix-directory" : mimetype unless @ar.nil?
  end
      
  def getcontentlength
    # Even though file_resource returns nil if collection?, at least one client doesn't like this.
    # (WebDAV plugin for Firefox)
    collection? ? 0 : @ar.size unless @ar.nil?
  end
   
  def data
    collection? ? nil : @ar.data unless @ar.nil?
  end

end