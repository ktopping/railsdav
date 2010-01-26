# Released under the MIT License.  See the LICENSE file for more details.
# Copyright (c) 2006 Stuart Eccles
# The act_as_railsdav method is attached to ActionController and can be used by calling act_as_railsdav on a controller

# class MyDavController < ActionController::Base
# 
#   act_as_railsdav
#
# The controller must then have a route of
# map.connect 'mydav/*path_info', :controller => 'my_dav', :action => 'webdav'
#
# it is then necessary to implement some or all of the following methods mkcol_for_path(path), write_content_to_path(path, content), 
# copy_to_path(resource, dest_path, depth), move_to_path(resource, dest_path, depth), get_resource_for_path(path)
#
# get_resource_for_path needs to return a WebDAVResource object such as FileWebDavResource
#
# To add webdav authentication to your controller just use
# class MyDavController < ActionController::Base
#   act_as_railsdav
#   before_filter :my_auth
#
#   def my_auth()
#       basic_auth_required {|username, password| session[:user] = User.your_authentication(username,password) }
#   end
#
#
require 'action_controller'
module Railsdav
  
  class Lock
    
    attr_accessor :type, :scope, :timeout, :depth, :timeout_units, :href, :token

    def initialize(args)      
      @type    = args[:type]
      @scope   = args[:scope]
      @timeout = args[:timeout]
      @href    = args[:href]  
      @depth   = 'Infinity'
      @timeout_units = 'Second'
      @token   = build_token(args[:id])
    end

    def timeout_full
      "#{self.timeout_units}-#{self.timeout}"
    end

    protected
    def build_token(text)
      require 'digest/md5'
      md5 = Digest::MD5.hexdigest(text.to_s).to_s
      'opaquelocktoken:'+md5[0,7]+'-'+md5[8,11]+'-'+md5[12,15]+'-'+md5[16,19]+'-'+md5[20,31]
    end
  end

  #TODO: Put this somewhere else!
  class FilesystemLockFactory
    def lock(path)
      Rails.logger.debug "Trying to LOCK " + path
      lockfile = lockfile_path path
      if File.exists? lockfile
        # actually, we should check if it has timed-out
        false
      else
        File.open lockfile, "w" do |f|
          if f.flock(File::LOCK_EX | File::LOCK_NB)
            # actually, the above returns 0 on success, but this is "true" according to ruby
            ret = Lock.new({:type => 'write', :scope => 'exclusive', :timeout => 60*60*5, :href => path, :id =>4})
            f.write(ret.token)
            if f.flock(File::LOCK_UN | File::LOCK_NB)
              ret
            else
              false
            end
          else
            false
          end
        end
      end
    end
    
    def unlock(path, token)
      Rails.logger.debug "Trying to UNLOCK " + path
      lockfile = lockfile_path path
      if !File.exists? lockfile
        false
      else
        File.open lockfile, "r" do |f|
          if f.flock(File::LOCK_EX | File::LOCK_NB)
            stored_token = f.read
            Rails.logger.debug "Tokens: " + stored_token + " == " + token + " ?"
            if (stored_token == token) then
              # actually, the above returns 0 on success, but this is "true" according to ruby
              # TODO: check that the lock token matches
              Rails.logger.debug "Deleting " + lockfile
              File.delete lockfile
              true
            else
              Rails.logger.debug "Tokens not equal!"
              false
            end
          else
            Rails.logger.debug "Cannot lock " + lockfile
            false
          end
        end
      end
    end
    
    def initialize
      # @lockRoot = File.join(ENV['RAILS_ROOT'], 'locks');
      # puts("RAILS_ROOT=" + RAILS_ROOT)
      @lockRoot = Rails.root.join("locks")
    end
    
    private
    def lockfile_path(path)
      ret = File.join(@lockRoot, path.gsub(/\//, "_"))
      Rails.logger.debug "lockfile_path =" + ret
      ret
    end
    
  end

  #TODO: Put this somewhere else!
  class ActiveRecordLockFactory
    
    def lock(path)
      Rails.logger.debug "ActiveRecordLockFactory. Trying to LOCK " + path
      ar = @ar_class.find_by_path path
      if ar
        # actually, we should check if it has timed-out
        false
      else
        ar = @ar_class.new({:path => path})
        ar.save!
        loc = Lock.new({:type => 'write', :scope => 'exclusive', :timeout => 60*60*5, :href => path, :id => ar.id})
        ar.token = loc.token
        ar.save!
        loc
      end
    end
    
    def unlock(path, token)
      Rails.logger.debug "ActiveRecordLockFactory. Trying to UNLOCK " + path
      ar = @ar_class.find_by_path path
      if !ar
        Rails.logger.debug "Cannot find lock!"
        false
      else
        if ar.token == token
          Rails.logger.debug "Deleting " + ar.to_s
          ar.delete
          true
        else
          Rails.logger.debug "Tokens not equal!"
          false
        end
      end
    end
    
    def initialize(class_name)
      @ar_class = eval(class_name)
    end
    
  end



  
    METHODS = %w(lock unlock options propfind proppatch mkcol delete put copy move)
    VERSIONS = %w(1 2)

    def self.append_features(base)
      super
      base.extend(ClassMethods)
    end 

    module ClassMethods
      def act_as_railsdav(options = {})
        class_inheritable_accessor :max_propfind_depth
        class_inheritable_accessor :dav_methods
        class_inheritable_accessor :dav_versions
        
        options[:extra_methods]         ||= []
        options[:extra_actions]         ||= []
        options[:extra_dav_versions]    ||= []
        
        #other methods allow for things like CalDav
        self.dav_methods = METHODS + options[:extra_methods] + options[:extra_actions]
        self.dav_versions = VERSIONS + options[:extra_dav_versions]
        
        class_inheritable_accessor :lock_factory
        if options[:lock_factory]
          self.lock_factory = options[:lock_factory]
        else
          self.lock_factory = FileSystemLockFactory.new
        end
        
        class_eval do 
          extend Railsdav::PropXMLMethods
        end
        include Railsdav::InstanceMethods
        include Railsdav::WebDavCallbacks
        hide_action(self.dav_methods.collect {|action| "webdav_#{action}"})
      end
    end
     
  module InstanceMethods   
     def webdav
        
       #we can get the method (as webdav has a lot of new methods) from the request
       webdav_method = request.head? ? "head" : request.method.to_s
       
       #get the standard information needed for webdav methods such as path and depth
       #the path needs to be unicode fixed
       @path_info = fix_path_info(request, params[:path_info].join("/"))
       @depth = get_depth
       
      begin
         #going to call the method for this webdav method 
         if respond_to?("webdav_#{webdav_method}", true)
           logger.debug("Responds to #{webdav_method}")
           __send__("webdav_#{webdav_method}")
         else
           #not one of our supported methods
           raise WebDavErrors::MethodNotAllowedError
         end
         
      rescue WebDavErrors::BaseError => webdav_error
          render :nothing => true, :status => webdav_error.http_status and return
      end
        
     end
     
     def webdav_options()
        response.headers['DAV'] = dav_versions.join(",")
        response.headers['MS-Author-Via'] = "DAV"
        response.headers["Allow"] = dav_methods.map{|o| o.upcase}.join(",")
        render  :nothing => true, :status => :ok and return
     end
     
     #Kieran git://github.com/jagthedrummer/railsdav.git
    def get_lock(path)
      #resource = get_resource_for_path(path)
      #return false unless resource.locked?
      lock_factory.lock(path)
    end
    
    def webdav_lock()
      logger.debug "Got here ONE!"
      @lock = get_lock(@path_info)
      if @lock
        response.headers["Lock-Token"] = "<#{@lock.token}>"
        response.headers["Content-Type"] = 'text/xml; charset="utf-8"'
        logger.debug "Got here!"
        logger.debug(render_to_string :inline => self.class.lock_xml, :layout => false, :type => :rxml, :status => 200)
        render :inline => self.class.lock_xml, :layout => false, :type => :rxml, :status => 200  and return
      else
        render  :nothing => true, :status => WebDavErrors::ForbiddenError and return
      end
    end
    
=begin
     def webdav_lock()
        #TODO implementation for now return a 200 OK
        @resource = get_resource_for_path(@path_info)
        lock = lock_factory.lock(@resource)
        render :nothing => true, :status => :ok and return
     end
=end

     def webdav_unlock()
        #TODO implementation for now return a 200 OK
        # @resource = get_resource_for_path(@path_info)
        # lock = lock_factory.unlock(@resource)
        lock_token = request.headers["Lock-Token"].gsub(/(^<)|(>$)/, "")
        logger.debug "lock_token=" + lock_token
        lock = lock_factory.unlock(@path_info, lock_token)
        # 204="No content"
        render :nothing => true, :status => 204 and return
     end
     
      def webdav_propfind()        
        
        unless request.raw_post.blank?
          #the request should be a XML document so parse it into a REXML document
          #not going to do anything with the document just going to get the 
          #resources to return all properties
          begin
            req_xml = REXML::Document.new request.raw_post
          rescue REXML::ParseException
            raise WebDavErrors::BadRequestBodyError
          end
        end
        
        #get all the resources requested for this path
        resource = get_resource_for_path(@path_info)
        
        raise WebDavErrors::NotFoundError if resource.nil?
        
        @resources = get_dav_resource_props(resource)
        
        response.headers["Content-Type"] = 'text/xml; charset="utf-8"'
        
        #render the Multistatus XML
        logger.debug(render_to_string :inline => self.class.propfind_xml, :layout => false, :type => :rxml, :status => 207)
        render :inline => self.class.propfind_xml, :layout => false, :type => :rxml, :status => 207  and return
      end
  
      def webdav_proppatch()
        @resource = get_resource_for_path(@path_info)
        
        raise WebDavErrors::NotFoundError if @resource.nil?
        
        begin
          #the request should be a XML document so parse it into a REXML document
          req_xml = REXML::Document.new request.raw_post
        rescue REXML::ParseException
          raise WebDavErrors::BadRequestBodyError
        end
        
        #params["propertyupdate"]["set"].each {|prop| prop["prop"]}
        
        @remove_properties = []
        @set_properties = []
        
        #get the xml elements used for propertyupdating remove and set
        ns = {""=>"DAV:"}
        REXML::XPath.each(req_xml, "/propertyupdate/remove/prop/*", ns){|e|
          @remove_properties << e
        }
        REXML::XPath.each(req_xml, "/propertyupdate/set/prop/*", ns){|e|
          @set_properties << e
        }
        
         response.headers["Content-Type"] = 'text/xml; charset="utf-8"'
         
         #render the Multistatus XML
         render :inline => self.class.proppatch_xml, :layout => false, :type => :rxml, :status => 207  and return
      end
  
      def webdav_mkcol()
         # need to check the content-type header to not allow invalid content types
          mkcol_ct = request.headers['Content-Type']
          if (!mkcol_ct.blank? && mkcol_ct != "httpd/unix-directory")
            raise WebDavErrors::UnSupportedTypeError
          end
          
          mkcol_for_path(@path_info)
          
          render :nothing => true, :status => :created
      end
  
      def webdav_delete()
        resource = get_resource_for_path(@path_info)
        unless resource.nil?
          resource.delete!
        else
          #Delete on a non-existant resource
          raise WebDavErrors::NotFoundError
        end
  
        render :nothing => true, :status => :created
      end
  
      def webdav_put()
        
         write_content_to_path(@path_info, request.raw_post)
  
         render :nothing => true, :status => :created and return
      end
  
      def webdav_copy()
        
         #Check the destination URI
         begin
          dest_uri = get_destination_uri
          dest_path = get_dest_path
	  #Bad Gateway it if the servers arnt the same
          #request.host_with_port does not work well as a test
          #since it will leave off :80 if it's a 'normal' http request
          raise WebDavErrors::BadGatewayError unless "#{request.host}:#{request.port}" == "#{dest_uri.host}:#{dest_uri.port}"
         rescue URI::InvalidURIError
          raise WebDavErrors::BadGatewayError
         end
          
          source_resource = get_resource_for_path(@path_info)

          #Not found if the source doesnt exist
          raise WebDavErrors::NotFoundError if source_resource.nil?
          
          dest_resource = get_resource_for_path(dest_path)

          raise WebDavErrors::PreconditionFailsError unless dest_resource.nil? || get_overwrite
          
          copy_to_path(source_resource, dest_path, @depth)

          dest_resource.nil? ? render(:nothing => true, :status => 201) : render(:nothing => true, :status => 204)
      end
  
      def webdav_move()
             #Check the destination URI
              begin
               dest_uri = get_destination_uri
               dest_path = get_dest_path
	       #Bad Gateway it if the servers arnt the same
               #request.host_with_port does not work well as a test
               #since it will leave off :80 if it's a 'normal' http request
               raise WebDavErrors::BadGatewayError unless "#{request.host}:#{request.port}" == "#{dest_uri.host}:#{dest_uri.port}"
              rescue URI::InvalidURIError
               raise WebDavErrors::BadGatewayError
              end
              
              source_resource = get_resource_for_path(@path_info)
  
              #Not found if the source doesnt exist
              raise WebDavErrors::NotFoundError if source_resource.nil?
              
              dest_resource = get_resource_for_path(dest_path)
  
              raise WebDavErrors::PreconditionFailsError unless dest_resource.nil? || get_overwrite
              
              move_to_path(source_resource, dest_path, @depth)
  
              dest_resource.nil? ? render(:nothing => true, :status => 201) : render(:nothing => true, :status => 204)
      end
      
      def webdav_get
          resource = get_resource_for_path(@path_info)
          raise WebDavErrors::NotFoundError if resource.blank?
          data_to_send = resource.data 
          raise WebDavErrors::NotFoundError if data_to_send.blank?
          response.headers["Last-Modified"] = resource.getlastmodified
          if data_to_send.kind_of? File
            send_file File.expand_path(data_to_send.path), :filename => resource.displayname, :stream => true
          else
            send_data data_to_send, :filename => resource.displayname unless data_to_send.nil?
          end
         
      end
      
      def webdav_head
        resource = get_resource_for_path(@path_info)
        raise WebDavErrors::NotFoundError if resource.blank?
        response.headers["Last-Modified"] = resource.getlastmodified
        render(:nothing => true, :status => :ok) and return  
      end
     
      ##############################################################################################################
       protected
       
       ##############################################################################################################
       #To be overidden by implementing controller
       #if they are not overidden it raises a ForbiddenError for the client
       #so a controller only needs to implement the methods it will support
       def mkcol_for_path(path)
          raise WebDavErrors::ForbiddenError
       end
       
       def write_content_to_path(path, content)
          raise WebDavErrors::ForbiddenError
       end
       
       def copy_to_path(resource, dest_path, depth)
          raise WebDavErrors::ForbiddenError
       end
       
       def move_to_path(resource, dest_path, depth)
          raise WebDavErrors::ForbiddenError
       end
       
       def get_resource_for_path(path)
          raise WebDavErrors::ForbiddenError
       end
       ##############################################################################################################
      
           def get_depth
             depth_head = request.headers['Depth'] 
             
             #default a big depth if infinity
             if (depth_head.nil?)
                depth = 1
             else
                depth = (depth_head == "infinity") ? 500 : depth_head.to_i
             end
             
             if max_propfind_depth.nil?
               depth = 500 if depth > 500
             else
               depth = self.class.max_propfind_depth if depth > self.class.max_propfind_depth
             end
             
             return depth
           end
           
           def get_destination_uri
             dest = request.headers['Destination']
             dest.last == "/" ? URI.parse(dest.to(dest.size-2)) : URI.parse(dest)
           end
           
           def get_dest_path
             if /^#{Regexp.escape(url_for(:only_path => true, :path_info => ""))}/ =~  get_destination_uri.path
                 return URI.unescape($')
             else
                 raise WebDavErrors::ForbiddenError
             end
           end
           
           def get_overwrite
             ov = request.headers['Overwrite']
             return (!ov.blank? and ov == 'T')
           end
  
           def get_dav_resource_props(resource)
              ret_set = Array.new
              @depth -= 1
              
              #add the resource for this path to the return set
              ret_set << resource
              
              if @depth >= 0 and !resource.children.nil?
                resource.children.each do |child|
                  ret_set.concat get_dav_resource_props(child) unless child.nil?
                end
              end
              
              return ret_set
           end
           
           def href_for_path(path)
             unless path.nil?
               new_path = path.clone
               new_path = new_path.from(1) if (new_path.first == "/")
               url_for(:only_path => true, :path_info => new_path)
             else
               url_for(:only_path => true)
             end
           end
            
           def basic_auth_required(realm='Web Password', error_message="Could't authenticate you") 
             username, passwd = get_auth_data
             # check if authorized
             # try to get user
             unless yield username, passwd
               # the user does not exist or the password was wrong
               headers["Status"] = "Unauthorized" 
               headers["WWW-Authenticate"] = "Basic realm=\"#{realm}\"" 
               render :nothing => true, :status => :unauthorized
             end 
           end 
           
           def get_auth_data 
             user, pass = '', '' 
             # extract authorisation credentials 
             if request.env.has_key? 'X-HTTP_AUTHORIZATION' 
               # try to get it where mod_rewrite might have put it 
               authdata = request.env['X-HTTP_AUTHORIZATION'].to_s.split 
             elsif request.env.has_key? 'HTTP_AUTHORIZATION' 
               # this is the regular location 
               authdata = request.env['HTTP_AUTHORIZATION'].to_s.split  
             end 
           
             # at the moment we only support basic authentication 
             if authdata and authdata[0] == 'Basic' 
               user, pass = Base64.decode64(authdata[1]).split(':')[0..1] 
             end 
             return [user, pass] 
          end
          
          def fix_path_info(req, path)
            logger.info("CONVERTED: " + Iconv.iconv('UTF-8', 'latin1', URI.unescape(path)).first)
            Iconv.iconv('UTF-8', 'latin1', URI.unescape(path)).first
            if req.env["HTTP_USER_AGENT"].match(/Microsoft|Windows/)
              logger.info("CONVERTED: " + Iconv.iconv('UTF-8', 'latin1', URI.unescape(path)).first)
              Iconv.iconv('UTF-8', 'latin1', URI.unescape(path)).first
            elsif req.env["HTTP_USER_AGENT"].match(/cadaver/)
              URI.unescape(URI.unescape(path))
            elsif req.env["HTTP_USER_AGENT"].match(/Darwin|Macintosh/)
              URI.unescape(path)
            else
              URI.unescape(path)
            end
          end
          
  end
end
