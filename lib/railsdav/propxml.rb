# Copyright (c) 2006 Stuart Eccles
# Released under the MIT License.  See the LICENSE file for more details.
module Railsdav
  
  module PropXMLMethods

    # The code I copied from here:
    #   http://blog.smartlogicsolutions.com/2008/07/01/microsoft-webdav-opens-document-as-read-only-when-using-railsdav/
    # mistakenly had 
    #  xml.D(:multistatus, {"xmlns:D" => "DAV:"}) do
    # instead of:
    #  xml.D(:prop, {"xmlns:D" => "DAV:"}) do
def lock_xml
<<EOLOCK_XML 
         xml.D(:prop, {"xmlns:D" => "DAV:"}) do
           xml.D :lockdiscovery do
             xml.D :activelock do
               xml.D :locktype do 
                 xml.D @lock.type.to_sym
               end
               xml.D :lockscope do 
                 xml.D @lock.scope.to_sym
               end
               xml.D :depth, @lock.depth
               xml.D :timeout, @lock.timeout_full               
               xml.D :locktoken do 
                 xml.D :href, @lock.token
               end               
               xml.D :lockroot do 
                 xml.D :href, @lock.href
               end
             end
           end
         end  
EOLOCK_XML
end    
    
    
        def propfind_xml
        <<EOPROPFIND_XML 
  xml.D(:multistatus, {"xmlns:D" => "DAV:"}) do
    @resources.each do |resource|
      xml.D :response do
        xml.D :href, resource.get_href
        xml.D :propstat do
          xml.D :prop do
            resource.get_properties.each do |property, value|
              xml.D(property, value)
            end
            xml.D :resourcetype do
              xml.D :collection if resource.collection?
            end
             				     #kieran added this
             				     xml.D :supportedlock do
             				       xml.D :lockentry do
             				         xml.D :lockscope do
             				           xml.D :exclusive
                             end
             				         xml.D :locktype do
             				           xml.D :write
                             end
                           end
                         end
             				     #<< kieran added this
          end
          xml.D :status, resource.status
        end
      end
    end
  end  
EOPROPFIND_XML
        end
        def proppatch_xml
          <<EOPROPPATCH_XML 
          xml.D(:multistatus, {"xmlns:D" => "DAV:"}) do
             xml.D :response do
                xml.D :href, URI.escape(@resource.get_href)
                for remove_property in @remove_properties
                    xml.D :propstat do
                      xml.D :prop do
                        xml.tag! remove_property.name.to_sym, remove_property.attributes
                      end
                      sym = ("remove_" + remove_property.name).to_sym
                      if @resource.respond_to?(sym)
                        xml.D(:status, @resource.__send__(sym))
                      else
                        xml.D :status, "HTTP/1.1 200 OK"
                      end
                    end
                end
                for set_property in @set_properties
                    xml.D :propstat do
                      xml.D :prop do
                        xml.D set_property.name.to_sym, set_property.attributes
                      end
                      sym = ("set_" + set_property.name).to_sym 
                      if @resource.respond_to?(sym)
                        method = @resource.method(sym)
                        if method.arity == 1 and set_property.children and set_property.children.size > 0
                            xml.D :status, method.call(set_property.children[0].to_s)
                        else
                            xml.D :status, method.call
                        end
                      else
                        xml.D :status, "HTTP/1.1 200 OK"
                      end
                    end
                end
       			    xml.D :responsedescription
             end
          end
EOPROPPATCH_XML
        end
  end
end