module AttrEncryptedEnvelope
  module Model
    def self.extended(base) # :nodoc:
      base.class_eval do
        attr_encrypted_options.merge!(
          encode: false,
          encryptor: ::AttrEncryptedEnvelope::Encryptor,
          class: base
        )
      end
    end

  protected

    def attr_encrypted(*attrs)
      super
      options = attrs.extract_options!
      
      # Define accessor for iv's, these are required by attr_encrypted but are encoded into a
      # single value with AttrEncryptedEnvelope 
      instance_methods_as_symbols = attribute_instance_methods_as_symbols
      attrs.each do |attribute|
        encrypted_attribute_name = (options[:attribute] ? options[:attribute] : [options[:prefix], attribute, options[:suffix]].join).to_sym
        iv_name = "#{encrypted_attribute_name}_iv".to_sym

        attr_reader iv_name unless instance_methods_as_symbols.include?(iv_name)
        attr_writer iv_name unless instance_methods_as_symbols.include?(:"#{iv_name}=")
      end
      
    end
  end
end