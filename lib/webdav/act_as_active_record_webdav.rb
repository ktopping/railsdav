# Copyright (c) 2006 Stuart Eccles
# Released under the MIT License.  See the LICENSE file for more details.

# The act_as_filewebdav allows for simple filesystem exposure to be added to any ActionController
#
# class FileDavController < ActionController::Base
#    act_as_filewebdav :base_dir => 'public'
# end
# 
# The base_dir parameter can be a string for a directory or a symbol for a method which is run for every request allowing the base directory
# to be changed based on the request
#
# If the parameter :absolute = true the :base_dir setting will be treated as an absolute path, otherwise the it will be taken as a directory 
# underneath the RAILS ROOT


module Railsdav
  
  module ActAsActiveRecordWebDav
    
    def self.append_features(base)
      super
      base.extend(ClassMethods)
    end 
  
    module ClassMethods
      def act_as_active_record_webdav(options = {})
        options[:model] ||= :webdav; #presume a table called webdav
        klassname = options[:model].to_s.camelize
        logger.debug "ActAsActiveRecordWebDav.act_as_active_record_webdav.klassname=#{klassname}"
        options[:model_class] = eval(klassname)
        logger.debug "ActAsActiveRecordWebDav.act_as_active_record_webdav.model_class=#{options[:model_class]}"
        
        # perform checks
        options[:model_class].respond_to?("find_by_path") or raise "#{klassname} class does not respond to find_by_path"
        inst = options[:model_class].new
        inst.respond_to?("data") or raise "#{klassname} instances do not respond to data"
        inst.respond_to?("size") or raise "#{klassname} instances do not respond to size"
        inst.respond_to?("is_directory") or raise "#{klassname} instances do not respond to is_directory"
        
        class_inheritable_accessor :options
        self.options = options
        class_eval do 
          act_as_railsdav options
        end
        max_propfind_depth = 1
        include ActAsActiveRecordWebDav::InstanceMethods
      end
    end
       
    module InstanceMethods
      
      private
      def get_active_record(path)
        res = self.options[:model_class].find_by_path(path); # or find by some other means?
        logger.debug "ActAsActiveRecordWebDav.get_active_record.res=#{res}"
        res
      end
      
      def create_active_record(path)
        res = self.options[:model_class].new({:path => path})
        logger.debug "ActAsActiveRecordWebDav.create_active_record.res=#{res}"
        res
      end
       
      protected
      #RFC2518:8.3
      def mkcol_for_path(path)
        begin
          file_path = sanitized_path(path)
          logger.debug "ActAsActiveRecordWebDav.mkcol_for_path.file_path=#{file_path}"
          #check for missing intermediate
          file_path.match(/(\/.*)\/.*$/)
          int_path = $1.nil? ? '/' : $1
          logger.debug "ActAsActiveRecordWebDav.mkcol_for_path.int_path=#{int_path}"
          unless get_active_record(int_path)
            raise WebDavErrors::ConflictError
          else
            ar = get_active_record(file_path) || create_active_record(file_path)
            ar.is_directory = true
            ar.size = 0
            ar.save!
            ar
          end
        rescue Errno::ENOENT, Errno::EACCES
          #Forbidden
          raise WebDavErrors::ForbiddenError
        rescue Errno::ENOSPC
          #Insufficient Storage
          raise WebDavErrors::InsufficientStorageError
        rescue Errno::EEXIST
          #Not Allowed 
          raise WebDavErrors::MethodNotAllowedError
        end
=begin
        begin
          file_path = santized_path(path)
          #check for missing intermediate
          path.match(/(.*)\/.*$/)
          int_path = $1.nil? ? '/' : $1
          unless File.exists?(santized_path(int_path))
            raise WebDavErrors::ConflictError
          else
            Dir.mkdir(file_path)
          end
        rescue Errno::ENOENT, Errno::EACCES
          #Forbidden
          raise WebDavErrors::ForbiddenError
        rescue Errno::ENOSPC
          #Insufficient Storage
          raise WebDavErrors::InsufficientStorageError
        rescue Errno::EEXIST
          #Not Allowed 
          raise WebDavErrors::MethodNotAllowedError
        end
=end
      end 
       
      def write_content_to_path(path, content)
        begin
          file_path = sanitized_path(path)
          ar = get_active_record(file_path) || create_active_record(file_path)
          logger.debug "ActAsActiveRecordWebDav.write_content_to_path.ar=#{ar}"
          ar.data = content
          ar.size = content.length
          ar.is_directory = false
          ar.save!
          #TODO catch proper errors
        rescue Errno::ENOENT
          #Conflict
          raise WebDavErrors::ConflictError
        rescue Errno::EPERM
          #Forbidden
          raise WebDavErrors::ForbiddenError
        end
      end
       
      def copy_to_path(resource, dest_path, depth)
        file_path = sanitized_path(dest_path)
        ar = get_active_record(file_path) || create_active_record(file_path)
        resource.copy!(ar, depth)
=begin
          #check for missing intermediate
          dest_path.match(/(.*)\/.*$/)
          int_path = $1.nil? ? '/' : $1
          unless File.exists?(santized_path(int_path))
            raise WebDavErrors::ConflictError
          else
            #remove anything existing at the destination path
            remove_existing_dest_path(dest_file_path)
            resource.copy!(dest_file_path, depth)
          end
=end
          
      end
       
      def move_to_path(resource, dest_path, depth)
        file_path = sanitized_path(dest_path)
        remove_existing_dest_path(file_path)
        resource.move!(file_path, depth)
=begin
         resource.copy!(ar, depth)
         
          dest_file_path = santized_path(dest_path)
          
          #check for missing intermediate
          dest_path.match(/(.*)\/.*$/)
          int_path = $1.nil? ? '/' : $1
          unless File.exists?(santized_path(int_path))
            raise WebDavErrors::ConflictError
          else
            #remove anything existing at the destination path
            remove_existing_dest_path(dest_file_path)
            resource.move!(dest_file_path, depth)
          end
=end    
      end
     
      def get_resource_for_path(path)
        logger.debug "ActAsActiveRecordWebDav.get_resource_for_path.path=#{path}"
        file_path = sanitized_path(path)
        ar = get_active_record(file_path)
        ar.nil? ? nil : ActiveRecordWebDavResource.new(ar, href_for_path(path))
=begin
        begin  
          abs_file_path = santized_path(path)           
          return nil unless File.exists?(abs_file_path)
          FileWebDavResource.new(abs_file_path, href_for_path(path))
        rescue Errno::EPERM
          raise WebDavErrors::ForbiddenError
        end
=end    
      end
     
      def sanitized_path(file_path = '/')
        if (file_path.match(/^\/.*/))
          file_path
        else
          "/" + file_path
        end
=begin
         # Resolve absolute path.
         if (self.options[:base_dir].is_a?(Symbol))
           file_root = self.send(options[:base_dir])
         else
           file_root = options[:base_dir].clone
#           file_root = file_root[1..-1] if (file_root.first == "/")
           file_root = file_root[0..-2] if (file_root.last == "/")
        end
         
         unless (self.options[:absolute])
           file_root = File.join(RAILS_ROOT,file_root)
         end
         
         path = File.expand_path(File.join(file_root, file_path))
         
         # Deny paths that dont include the original path
         # TODO more work on the santized
         raise WebDavErrors::ForbiddenError unless path =~ /^#{File.expand_path(file_root)}/ 
         
         return path
=end
      end
       
      def remove_existing_dest_path(dest_file_path)
        file_path = sanitized_path(dest_file_path)
        ar = get_active_record(file_path)
        ar.delete unless ar.nil?
=begin
       if (File.exists?(dest_file_path))
           begin
              FileUtils.rm_rf(dest_file_path)
            rescue Errno::ENOENT
               #Conflict
               raise WebDavErrors::ConflictError
            rescue Errno::EPERM
               #Forbidden
               raise WebDavErrors::ForbiddenError
            end
        end
=end
      end
    end
  end
end
