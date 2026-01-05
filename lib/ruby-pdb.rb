require 'libbin'
require 'stringio'
require 'set'
require 'float-formats'

# https://llvm.org/docs/PDB/index.html
class PDBFile < LibBin::Structure

  def self.read_stream(f, size, block_size, blocks)
    i = 0
    remaining = size
    str = "".b
    while remaining > 0
      f.seek(blocks[i]*block_size)
      str << f.read([remaining, block_size].min)
      remaining -= [remaining, block_size].min
      i+=1
    end
    raise unless size = str.size
    StringIO.new(str, 'rb')
  end

  class StreamDirectory < LibBin::Structure
    uint32_le :num_streams
    uint32_le :stream_sizes, length: 'num_streams'
    uint32_le :stream_blocks, length: '(stream_sizes[__iterator] + ..\super_block\block_size - 1) / ..\super_block\block_size', count: 'num_streams', sequence: true, condition: 'stream_sizes[__iterator] != 0xFFFFFFFF'
  end

  class GUID < LibBin::Structure
    uint32_le :data1
    uint16_le :data2
    uint16_le :data3
    uint8     :data4, length: 8
    def to_s
      "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x" % ([data1, data2, data3] + data4)
    end
  end

  class InfoStreamHeader < LibBin::Structure
    enum           :version, { VC2: 19941610, VC4: 19950623, VC41: 19950814, VC50: 19960307, VC98: 19970604, VC70Dep: 19990604, VC70: 20000404, VC80: 20030901, VC110: 20091201, VC140: 20140508 }, size: 32, big: false
    uint32_le      :signature
    uint32_le      :age
    register_field :unique_id, GUID
  end

  class BitVector < LibBin::Structure
    uint32_le :word_count
    uint32_le :bit_vector, length: 'word_count'
    def [](index)
      bit_vector[index/32] >> (index%32) & 1
    end

    def to_s
      bit_vector.map { |v| "%032b" % [v] }.reverse.join
    end

    def indices
      @indices ||= bit_vector.reduce([[],0]) { |(list, i), v| [list + 32.times.select { |j| ((v >> j) & 1) == 1 }.map { |j| j+i }, i+32] }.first
    end
  end

  class StringHash < LibBin::Structure
    uint32_le      :num_string_buffer_bytes
    string         :string_buffer, 'num_string_buffer_bytes'
    uint32_le      :size
    uint32_le      :capacity
    register_field :present, BitVector
    register_field :deleted, BitVector
    uint32_le      :key_value_pairs, length: 2, count: 'size'

    def to_h
      @h ||= begin
        deleted_indices = deleted.indices.to_set
        present_indices = present.indices
        key_value_pairs.each_with_index.filter_map { |(k, v), i| [string_buffer[k..-1].unpack("Z*").first, v] unless deleted_indices.include?(present_indices[i]) }.to_h
      end
    end
  end

  class InfoStream < LibBin::Structure
    register_field :header, InfoStreamHeader
    register_field :named_stream_map, StringHash
    uint32_le      :num_feature_sigs
    enum           :feature_sigs, { VC110: 20091201, VC140: 20140508, NoTypeMerge: 0x4D544F4E, MinimalDebugInfo: 0x494E494D }, size: 32, big: false, length: 'num_feature_sigs'
  end

  class NameStream < LibBin::Structure
    uint32_le :signature, expect: 0xEFFEEFFE
    uint32_le :hasg_version
    uint32_le :num_string_buffer_bytes
    string    :string_buffer, 'num_string_buffer_bytes'
    uint32_le :num_strings
    uint32_le :string_indices, length: 'num_strings'
    uint32_le :name_count

    def strings
      @strings ||= string_indices.map { |index| string_buffer[index..-1].unpack("Z*").first }
    end
  end

  class TpiStream < LibBin::Structure
    class Header < LibBin::Structure
      uint32_le :version
      uint32_le :header_size
      uint32_le :type_index_begin
      uint32_le :type_index_end
      uint32_le :type_record_bytes
      int16_le  :hash_stream_index
      int16_le  :hash_aux_stream_index
      uint32_le :hash_key_size
      uint32_le :num_hash_buckets
      int32_le  :hash_value_buffer_offset
      uint32_le :hash_value_buffer_length
      int32_le  :index_offset_buffer_offset
      uint32_le :index_offset_buffer_length
      int32_le  :hash_adj_buffer_offset
      uint32_le :hash_adj_buffer_length
    end

    class Record < LibBin::Structure
      class Scalar < LibBin::Structure
        LF_NUMERIC = 0x8000
        Type = Class::new(LibBin::Structure::Enum) do |c|
          c.type = LibBin::Structure::UInt16_LE
          c.map = { LF_CHAR:       0x8000,
                    LF_SHORT:      0x8001,
                    LF_USHORT:     0x8002,
                    LF_LONG:       0x8003,
                    LF_ULONG:      0x8004,
                    LF_REAL32:     0x8005,
                    LF_REAL64:     0x8006,
                    LF_REAL80:     0x8007,
                    LF_REAL128:    0x8008,
                    LF_QUADWORD:   0x8009,
                    LF_UQUADWORD:  0x800a,
                    LF_REAL48:     0x800b,
                    LF_COMPLEX32:  0x800c,
                    LF_COMPLEX64:  0x800d,
                    LF_COMPLEX80:  0x800e,
                    LF_COMPLEX128: 0x800f,
                    LF_VARSTRING:  0x8010,

                    LF_OCTWORD:    0x8017,
                    LF_UOCTWORD:   0x8018,
                    LF_DECIMAL:    0x8019,
                    LF_DATE:       0x801a,
                    LF_UTF8STRING: 0x801b,
                    LF_REAL16:     0x801c,
                  }
        end
        SIZE_MAP = {
          LF_CHAR:        1,
          LF_SHORT:       2,
          LF_USHORT:      2,
          LF_LONG:        4,
          LF_ULONG:       4,
          LF_REAL32:      4,
          LF_REAL64:      8,
          LF_REAL80:     10,
          LF_REAL128:    16,
          LF_QUADWORD:    8,
          LF_UQUADWORD:   8,
          LF_REAL48:      6,
          LF_COMPLEX32:   8,
          LF_COMPLEX64:  16,
          LF_COMPLEX80:  20,
          LF_COMPLEX128: 32,

          LF_OCTWORD:    16,
          LF_UOCTWORD:   16,
          LF_DECIMAL:    16,
          LF_DATE:        8,
          LF_REAL16:      2,

        }
        uint16_le :leaf
        uint16_le :len, condition: 'type == :LF_VARSTRING'
        string    :buff, 'type == :LF_VARSTRING ? len : PDBFile::TpiStream::Record::Scalar::SIZE_MAP[type]', condition: 'leaf >= PDBFile::TpiStream::Record::Scalar::LF_NUMERIC'

        def type
          Type.instance_variable_get(:@map_to)[leaf]
        end

        def value
          @value ||= begin
            if leaf < LF_NUMERIC
              leaf
            else
              case type
              when :LF_CHAR
                buff.unpack('c').first
              when :LF_SHORT
                buff.unpack('s<').first
              when :LF_USHORT
                buff.unpack('S<').first
              when :LF_LONG
                buff.unpack('l<').first
              when :LF_ULONG
                buff.unpack('L<').first
              when :LF_REAL32
                buff.unpack('e').first
              when :LF_REAL64
                buff.unpack('E').first
              when :LF_REAL80
                Flt::IEEE_binary80.from_bytes(buff).to(BigDecimal, :exact)
              when :LF_REAL128
                Flt::IEEE_binary128.from_bytes(buff).to(BigDecimal, :exact)
              when :LF_QUADWORD
                buff.unpack('q<').first
              when :LF_UQUADWORD
                buff.unpack('Q<').first
              when :LF_REAL48
                Flt::BORLAND48.from_bytes(buff).to(Float, :exact)
              when :LF_COMPLEX32
                Complex.rect(*buff.unpack('ee'))
              when :LF_COMPLEX64
                Complex.rect(*buff.unpack('EE'))
              when :LF_COMPLEX80
                [Flt::IEEE_binary80.from_bytes(buff[ 0.. 9]).to(BigDecimal, :exact),
                 Flt::IEEE_binary80.from_bytes(buff[10..19]).to(BigDecimal, :exact)]
              when :LF_COMPLEX128
                [Flt::IEEE_binary128.from_bytes(buff[ 0..15]).to(BigDecimal, :exact),
                 Flt::IEEE_binary128.from_bytes(buff[16..31]).to(BigDecimal, :exact)]
              when :LF_VARSTRING
                buff.dup
              when :LF_OCTWORD
                buff.unpack('Q<q<').each_with_index.reduce(0) { |memo, (v, i)| memo |= v << (i*64) }
              when :LF_UOCTWORD
                buff.unpack('Q<Q<').each_with_index.reduce(0) { |memo, (v, i)| memo |= v << (i*64) }
              when :LF_DECIMAL #TODO
                buff.bytes
              when :LF_DATE
                buff.unpack('E').first
              when :LF_UTF8STRING
                buff.dup.force_encoding('utf-8')
              when :LF_REAL16
                Flt::IEEE_binary16.from_bytes(buff).to(Float, :exact)
              else
                raise "Unsupported numeric value."
              end
            end
          end
        end
      end

      Prop = Class::new(LibBin::Structure::Bitfield) do |c|
        c.type = LibBin::Structure::UInt16_LE
        c.map = { packed:        1, # true if structure is packed
                  ctor:          1, # true if constructors or destructors present
                  ovlops:        1, # true if overloaded operators present
                  isnested:      1, # true if this is a nested class
                  cnested:       1, # true if this class contains nested types
                  opassign:      1, # true if overloaded assignment (=)
                  opcast:        1, # true if casting methods
                  fwdref:        1, # true if forward reference (incomplete defn) # Look for matching unique name definition, or name definition if later doesn't exist
                  scoped:        1, # scoped definition
                  hasuniquename: 1, # true if there is a decorated name following the regular name
                  sealed:        1, # true if class cannot be used as a base class
                  hfa:           2, # CV_HFA_e
                  intrinsic:     1, # true if class is an intrinsic type (e.g. __m128d)
                  mocom:         2, # CV_MOCOM_UDT_e
                }
      end

      class VTShape < LibBin::Structure
        Desc = Class::new(LibBin::Structure::Enum) do |c|
          c.type = LibBin::Structure::UInt8
          c.map = {  CV_VTS_near:   0x00,
                     CV_VTS_far:    0x01,
                     CV_VTS_thin:   0x02,
                     CV_VTS_outer:  0x03,
                     CV_VTS_meta:   0x04,
                     CV_VTS_near32: 0x05,
                     CV_VTS_far32:  0x06,
                     CV_VTS_unused: 0x07,
                   }
        end
        uint16_le :count
        uint8     :descbytes, length: lambda { count/2 + count%2 }

        def descriptors
          @descriptors ||= begin
            res = descbytes.flat_map { |b| [(b & 0xf0)>>4, b & 0xf] }
            res.pop if count.odd?
            res.map { |v| Desc.instance_variable_get(:@map_to)[v] }
          end
        end
      end

      Mod = Class::new(LibBin::Structure::Bitfield) do |c|
        c.type = LibBin::Structure::UInt16_LE
        c.map = { const: 1,
                  volatile: 1,
                  unaligned: 1,
                  unused:13,
                }
      end

      class Modifier < LibBin::Structure
        uint32_le      :type
        register_field :attr, Mod

        def const?
          attr.const == 1
        end

        def volatile?
          attr.volatile == 1
        end

        def unaligned?
          attr.unaligned == 1
        end
      end

      class Pointer < LibBin::Structure
        Type = Class::new(LibBin::Structure::Enum) do |c|
          c.type = LibBin::Structure::Int8
          c.map = { CV_PTR_NEAR:          0x00, # 16 bit pointer
                    CV_PTR_FAR:           0x01, # 16:16 far pointer
                    CV_PTR_HUGE:          0x02, # 16:16 huge pointer
                    CV_PTR_BASE_SEG:      0x03, # based on segment
                    CV_PTR_BASE_VAL:      0x04, # based on value of base
                    CV_PTR_BASE_SEGVAL:   0x05, # based on segment value of base
                    CV_PTR_BASE_ADDR:     0x06, # based on address of base
                    CV_PTR_BASE_SEGADDR:  0x07, # based on segment address of base
                    CV_PTR_BASE_TYPE:     0x08, # based on type
                    CV_PTR_BASE_SELF:     0x09, # based on self
                    CV_PTR_NEAR32:        0x0a, # 32 bit pointer
                    CV_PTR_FAR32:         0x0b, # 16:32 pointer
                    CV_PTR_64:            0x0c, # 64 bit pointer
                    CV_PTR_UNUSEDPTR:     0x0d, # first unused pointer type
                  }
        end
        Mode = Class::new(LibBin::Structure::Enum) do |c|
          c.type = LibBin::Structure::Int8
          c.map = { CV_PTR_MODE_PTR:      0x00, # "normal" pointer
                    CV_PTR_MODE_REF:      0x01, # "old" reference
                    CV_PTR_MODE_LVREF:    0x01, # l-value reference
                    CV_PTR_MODE_PMEM:     0x02, # pointer to data member
                    CV_PTR_MODE_PMFUNC:   0x03, # pointer to member function
                    CV_PTR_MODE_RVREF:    0x04, # r-value reference
                    CV_PTR_MODE_RESERVED: 0x05, # first unused pointer mode
                  }
        end
        class Base < LibBin::Structure #Should be Union
          class MemberInfo < LibBin::Structure
            uint32_le :pmclass
            enum :pmenum, { CV_PMTYPE_Undef:      0x00, # not specified (pre VC8)
                            CV_PMTYPE_D_Single:   0x01, # member data, single inheritance
                            CV_PMTYPE_D_Multiple: 0x02, # member data, multiple inheritance
                            CV_PMTYPE_D_Virtual:  0x03, # member data, virtual inheritance
                            CV_PMTYPE_D_General:  0x04, # member data, most general
                            CV_PMTYPE_F_Single:   0x05, # member function, single inheritance
                            CV_PMTYPE_F_Multiple: 0x06, # member function, multiple inheritance
                            CV_PMTYPE_F_Virtual:  0x07, # member function, virtual inheritance
                            CV_PMTYPE_F_General:  0x08, # member function, most general
                          }, size: 16, signed: false, big: false
          end
          class BaseType < LibBin::Structure
            uint32_le :index
            uint8     :name, length: 1
          end
          register_field :pm, MemberInfo
#          uint16_le      :bseg
#          uint8          :sym, length: 1
#          register_field :btype, BaseType
        end

        uint32_le :utype
        bitfield  :attributes, { type:         5,
                                 mode:         3,
                                 is_flat:      1,
                                 is_volatile:  1,
                                 is_const:     1,
                                 is_unaligned: 1,
                                 is_restrict:  1,
                                 size:         6,
                                 is_mocom:     1,
                                 is_lref:      1,
                                 is_rref:      1,
                                 unused:      10 }, size: 32, big: false
#        register_field :base, Base

        def type
          Type.instance_variable_get(:@map_to)[attributes.type]
        end

        def mode
          Type.instance_variable_get(:@map_to)[attributes.mode]
        end

        def flat?
          attributes.is_flat == 1
        end

        def volatile?
          attributes.is_volatile == 1
        end

        def const?
          attributes.is_const == 1
        end

        def unaligned?
          attributes.is_unaligned == 1
        end

        def restrict?
          attributes.is_restrict == 1
        end

        def size
          attributes.size
        end

        def mocom?
          attributes.is_mocom == 1
        end

        def lref?
          attributes.is_lref == 1
        end

        def rref?
          attributes.is_rref == 1
        end
      end

      CallType = Class::new(LibBin::Structure::Enum) do |c|
        c.type = LibBin::Structure::UInt8
        c.map = { CV_CALL_NEAR_C:      0x00, # near right to left push, caller pops stack
                  CV_CALL_FAR_C:       0x01, # far right to left push, caller pops stack
                  CV_CALL_NEAR_PASCAL: 0x02, # near left to right push, callee pops stack
                  CV_CALL_FAR_PASCAL:  0x03, # far left to right push, callee pops stack
                  CV_CALL_NEAR_FAST:   0x04, # near left to right push with regs, callee pops stack
                  CV_CALL_FAR_FAST:    0x05, # far left to right push with regs, callee pops stack
                  CV_CALL_SKIPPED:     0x06, # skipped (unused) call index
                  CV_CALL_NEAR_STD:    0x07, # near standard call
                  CV_CALL_FAR_STD:     0x08, # far standard call
                  CV_CALL_NEAR_SYS:    0x09, # near sys call
                  CV_CALL_FAR_SYS:     0x0a, # far sys call
                  CV_CALL_THISCALL:    0x0b, # this call (this passed in register)
                  CV_CALL_MIPSCALL:    0x0c, # Mips call
                  CV_CALL_GENERIC:     0x0d, # Generic call sequence
                  CV_CALL_ALPHACALL:   0x0e, # Alpha call
                  CV_CALL_PPCCALL:     0x0f, # PPC call
                  CV_CALL_SHCALL:      0x10, # Hitachi SuperH call
                  CV_CALL_ARMCALL:     0x11, # ARM call
                  CV_CALL_AM33CALL:    0x12, # AM33 call
                  CV_CALL_TRICALL:     0x13, # TriCore Call
                  CV_CALL_SH5CALL:     0x14, # Hitachi SuperH-5 call
                  CV_CALL_M32RCALL:    0x15, # M32R Call
                  CV_CALL_CLRCALL:     0x16, # clr call
                  CV_CALL_INLINE:      0x17, # Marker for routines always inlined and thus lacking a convention
                  CV_CALL_NEAR_VECTOR: 0x18, # near left to right push with regs, callee pops stack
                  CV_CALL_RESERVED:    0x19  # first unused call enumeration
                }
      end

      FuncAttr = Class::new(LibBin::Structure::Bitfield) do |c|
        c.type = LibBin::Structure::UInt8
        c.map = { cxxreturnudt: 1, # true if C++ style ReturnUDT
                  ctor:         1, # true if func is an instance constructor
                  ctorvbase:    1, # true if func is an instance constructor of a class with virtual bases
                  unused:       5, # unused
                }
      end

      module FuncAttrMod
        def cxxreturnudt?
          funcattr.cxxreturnudt == 1
        end

        def ctor?
          funcattr.ctor == 1
        end

        def ctorvbase?
          funcattr.ctorvbase == 1
        end
      end

      class Procedure < LibBin::Structure
        include FuncAttrMod
        uint32_le      :rvtype             # type index of return value
        register_field :calltype, CallType # calling convention (CV_call_t)
        register_field :funcattr, FuncAttr # attributes
        uint16_le      :parmcount          # number of parameters
        uint32_le      :arglist            # type index of argument list
      end

      class MemberFunction < LibBin::Structure
        include FuncAttrMod
        uint32_le      :rvtype             # type index of return value
        uint32_le      :classtype          # type index of containing class
        uint32_le      :thistype           # type index of this pointer (model specific)
        register_field :calltype, CallType # calling convention (CV_call_t)
        register_field :funcattr, FuncAttr # attributes
        uint16_le      :parmcount          # number of parameters
        uint32_le      :arglist            # type index of argument list
        int32_le       :thisadjust         # this adjuster (long because pad required anyway)
      end

      class ArgList < LibBin::Structure
        uint32_le :count
        uint32_le :arg, length: lambda { count }
      end

      class Enum < LibBin::Structure
        uint16_le      :count
        register_field :property, Prop
        uint32_le      :utype
        uint32_le      :field
        string         :name
        string         :unique_name, condition: 'property.hasuniquename == 1'
      end

      AccessProtection = Class::new(LibBin::Structure::Enum) do |c|
        c.type = LibBin::Structure::Int8
        c.map = { ACCESS_NONE:    0,
                  ACCESS_PRIVATE: 1,
                  ACCESS_PROTECT: 2,
                  ACCESS_PUBLIC:  3,
                }
      end

      MethodProperties = Class::new(LibBin::Structure::Enum) do |c|
        c.type = LibBin::Structure::Int8
        c.map = { CV_MTvanilla:   0x00,
                  CV_MTvirtual:   0x01,
                  CV_MTstatic:    0x02,
                  CV_MTfriend:    0x03,
                  CV_MTintro:     0x04,
                  CV_MTpurevirt:  0x05,
                  CV_MTpureintro: 0x06,
                }
      end

      FieldAttribute = Class::new(LibBin::Structure::Bitfield) do |c|
        c.type = LibBin::Structure::UInt16_LE
        c.map = { access:      2, # access protection CV_access_t
                  mprop:       3, # method properties CV_methodprop_t
                  pseudo:      1, # compiler generated fcn and does not exist
                  noinherit:   1, # true if class cannot be inherited
                  noconstruct: 1, # true if class cannot be constructed
                  compgenx:    1, # compiler generated fcn and does exist
                  sealed:      1, # true if method cannot be overridden
                  unused:      6, # unused
                }
      end

      class FieldList < LibBin::Structure
        LF_BCLASS     = 0x1400
        LF_VBCLASS    = 0x1401
        LF_IVBCLASS   = 0x1402
        LF_INDEX      = 0x1404
        LF_VFUNCTAB   = 0x1409
        LF_ENUMERATE  = 0x1502
        LF_MEMBER     = 0x150d
        LF_STMEMBER   = 0x150e
        LF_METHOD     = 0x150f
        LF_NESTTYPE   = 0x1510
        LF_ONEMETHOD  = 0x1511
        LF_BINTERFACE = 0x151a
        LF_PAD0       =   0xf0

        attr_accessor :list

        class BaseClass < LibBin::Structure
          uint16_le      :leaf, expect: lambda { |v| [LF_BCLASS, LF_BINTERFACE].include?(v) }
          register_field :attr, FieldAttribute
          uint32_le      :index
          register_field :offset, Scalar
        end

        class VirtualBaseClass < LibBin::Structure
          uint16_le      :leaf, expect: lambda { |v| [LF_VBCLASS, LF_IVBCLASS].include?(v) }
          register_field :attr, FieldAttribute
          uint32_le      :index
          uint32_le      :vbptr
          register_field :offset_vbp, Scalar
          register_field :offset_vbte, Scalar
        end

        class Index < LibBin::Structure
          uint16_le      :leaf, expect: LF_INDEX
          uint16_le      :pad, expect: 0
          uint32_le      :index
        end

        class VirtualFuntionTable < LibBin::Structure
          uint16_le      :leaf, expect: LF_VFUNCTAB
          uint16_le      :pad, expect: 0
          uint32_le      :type
        end

        class Enumerate < LibBin::Structure
          uint16_le      :leaf, expect: LF_ENUMERATE
          register_field :attr, FieldAttribute
          register_field :value, Scalar
          string         :name
        end

        class Member < LibBin::Structure
          uint16_le      :leaf, expect: LF_MEMBER
          register_field :attr, FieldAttribute
          uint32_le      :index
          register_field :offset, Scalar
          string         :name
        end

        class StaticMember < LibBin::Structure
          uint16_le      :leaf, expect: LF_STMEMBER
          register_field :attr, FieldAttribute
          uint32_le      :index
          string         :name
        end

        class Method < LibBin::Structure
          uint16_le      :leaf, expect: LF_METHOD
          uint16_le      :count
          uint32_le      :method_list
          string         :name
        end

        class NestedType < LibBin::Structure
          uint16_le      :leaf, expect: LF_NESTTYPE
          uint16_le      :pad, expect: 0
          uint32_le      :index
          string         :name
        end

        class OneMethod < LibBin::Structure
          uint16_le      :leaf, expect: LF_ONEMETHOD
          register_field :attr, FieldAttribute
          uint32_le      :index
          uint32_le      :offset, condition: lambda { [:CV_MTintro, :CV_MTpureintro].include?(MethodProperties.instance_variable_get(:@map_to)[attr.mprop]) }
          string         :name
        end

        def self.load(input, input_big = LibBin::default_big?, *args)
          res = super
          res.list = []
          while !input.eof?
            while (b = input.getbyte) && b >= LF_PAD0
            end
            input.ungetbyte(b) if b
            break if input.eof?
            pos = input.pos
            leaf = input.read(2).unpack('S<').first
            input.pos = pos
            case leaf
            when LF_BCLASS
              res.list.push(BaseClass.load(input))
            when LF_VBCLASS, LF_IVBCLASS
              res.list.push(VirtualBaseClass.load(input))
            when LF_INDEX
              res.list.push(Index.load(input))
            when LF_VFUNCTAB
              res.list.push(VirtualFuntionTable.load(input))
            when LF_ENUMERATE
              res.list.push(Enumerate.load(input))
            when LF_MEMBER
              res.list.push(Member.load(input))
            when LF_STMEMBER
              res.list.push(StaticMember.load(input))
            when LF_METHOD
              res.list.push(Method.load(input))
            when LF_NESTTYPE
              res.list.push(NestedType.load(input))
            when LF_ONEMETHOD
              res.list.push(OneMethod.load(input))
              m = res.list.last
            else
              $stderr.puts "Unsupported field 0x#{leaf.to_s(16)}"
              break
            end
          end
          res
        end
      end

      class BitField < LibBin::Structure
        uint32_le :type
        uint8     :length
        uint8     :position
      end

      class MethodList < LibBin::Structure
        attr_accessor :list

        class Method < LibBin::Structure
          register_field :attr, FieldAttribute
          uint16_le      :pad, expect: 0
          uint32_le      :index
          uint32_le      :offset, condition: lambda { [:CV_MTintro, :CV_MTpureintro].include?(MethodProperties.instance_variable_get(:@map_to)[attr.mprop]) }
        end

        def self.load(input, input_big = LibBin::default_big?, *args)
          res = super
          res.list = []
          while !input.eof?
            res.list.push(Method.load(input))
          end
          res
        end
      end

      class Array < LibBin::Structure
        uint32_le      :elemtype
        uint32_le      :idxtype
        register_field :size, Scalar
        string         :name
      end

      class Class < LibBin::Structure
        uint16_le      :count
        register_field :property, Prop
        uint32_le      :field
        uint32_le      :derived
        uint32_le      :vshape
        register_field :size, Scalar
        string         :name
      end

      class Structure < LibBin::Structure
        uint16_le      :count
        register_field :property, Prop
        uint32_le      :field
        uint32_le      :derived
        uint32_le      :vshape
        register_field :size, Scalar
        string         :name
      end

      class Union < LibBin::Structure
        uint16_le      :count
        register_field :property, Prop
        uint32_le      :field
        register_field :size, Scalar
        string         :name
      end

      class Interface < LibBin::Structure
        uint16_le      :count
        register_field :property, Prop
        uint32_le      :field
        uint32_le      :derived
        uint32_le      :vshape
        register_field :size, Scalar
        string         :name
      end

      uint16_le :len
      enum      :kind, { LF_VTSHAPE:          0x000a,
                         LF_LABEL:            0x000e,
                         LF_ENDPRECOMP:       0x0014,
                         LF_MODIFIER:         0x1001,
                         LF_POINTER:          0x1002,
                         LF_PROCEDURE:        0x1008,
                         LF_MFUNCTION:        0x1009,
                         LF_ARGLIST:          0x1201,
                         LF_FIELDLIST:        0x1203,
                         LF_BITFIELD:         0x1205,
                         LF_METHODLIST:       0x1206,
                         LF_ARRAY:            0x1503,
                         LF_CLASS:            0x1504,
                         LF_STRUCTURE:        0x1505,
                         LF_UNION:            0x1506,
                         LF_ENUM:             0x1507,
                         LF_PRECOMP:          0x1509,
                         LF_TYPESERVER2:      0x1515,
                         LF_INTERFACE:        0x1519,
                         LF_VFTABLE:          0x151d,
                         LF_FUNC_ID:          0x1601,
                         LF_MFUNC_ID:         0x1602,
                         LF_BUILDINFO:        0x1603,
                         LF_SUBSTR_LIST:      0x1604,
                         LF_STRING_ID:        0x1605,
                         LF_UDT_SRC_LINE:     0x1606,
                         LF_UDT_MOD_SRC_LINE: 0x1607,
                       }, size: 16, big: false
      string :data, 'len - 2'
      def field
        @field ||=
          case kind
          when :LF_VTSHAPE
            VTShape.load(StringIO.new(data, 'rb'))
          when :LF_MODIFIER
            Modifier.load(StringIO.new(data, 'rb'))
          when :LF_POINTER
            Pointer.load(StringIO.new(data, 'rb'))
          when :LF_PROCEDURE
            Procedure.load(StringIO.new(data, 'rb'))
          when :LF_MFUNCTION
            MemberFunction.load(StringIO.new(data, 'rb'))
          when :LF_ARGLIST
            ArgList.load(StringIO.new(data, 'rb'))
          when :LF_FIELDLIST
            FieldList.load(StringIO.new(data, 'rb'))
          when :LF_BITFIELD
            BitField.load(StringIO.new(data, 'rb'))
          when :LF_METHODLIST
            MethodList.load(StringIO.new(data, 'rb'))
          when :LF_ARRAY
            Array.load(StringIO.new(data, 'rb'))
          when :LF_CLASS
            Class.load(StringIO.new(data, 'rb'))
          when :LF_STRUCTURE
            Structure.load(StringIO.new(data, 'rb'))
          when :LF_UNION
            Union.load(StringIO.new(data, 'rb'))
          when :LF_ENUM
            Enum.load(StringIO.new(data, 'rb'))
          when :LF_INTERFACE
            Interface.load(StringIO.new(data, 'rb'))
          else
            $stderr.puts "Unsupported record #{kind}"
            nil
          end
      end
    end
    register_field :header, Header
    register_field :records, Record, count: 'header\type_index_end - header\type_index_begin'
  end

  class SrcHeaderBlockHeader < LibBin::Structure
    uint32_le :version
    uint32_le :size
    uint64    :file_time
    uint32_le :age
    uint8     :padding, length: 44
  end

  class SrcHeaderBlockEntry < LibBin::Structure
    uint32_le :size
    uint32_le :version, expect: 19980827
    uint32_le :crc
    uint32_le :file_size
    uint32_le :file_name_index
    uint32_le :obj_name_index
    uint32_le :virtual_file_name_index
    enum      :compression, {None: 0, RunLengthEncoded: 1, Huffman: 2, LZ: 3, DotNet: 101}, size: 8
    uint8     :is_virtual
    uint16    :padding
    uint8     :reserved, length: 8
  end

  class SrcHeaderBlockEntryHashEntry < LibBin::Structure
    uint32_le      :key
    register_field :value, SrcHeaderBlockEntry
  end

  class SrcHeaderBlockEntryHash < LibBin::Structure
    uint32_le      :size
    uint32_le      :capacity
    register_field :present, BitVector
    register_field :deleted, BitVector
    register_field :key_value_pairs, SrcHeaderBlockEntryHashEntry, count: 'size'

    def to_h
      @h ||= begin
        deleted_indices = deleted.indices.to_set
        present_indices = present.indices
        key_value_pairs.each_with_index.filter_map { |pair, i| [pair.key, par.value] unless deleted_indices.include?(present_indices[i]) }.to_h
      end
    end
  end

  class SrcHeaderBlock < LibBin::Structure
    register_field :header, SrcHeaderBlockHeader
    register_field :entries_hash, SrcHeaderBlockEntryHashEntry
  end

  MachineType = Class::new(LibBin::Structure::Enum) do |c|
    c.type = LibBin::Structure::UInt16_LE
    c.map = { IMAGE_FILE_MACHINE_TARGET_HOST: 0x0001, # Interacts with the host and not a WOW64 guest
              IMAGE_FILE_MACHINE_I386:        0x014c, # Intel 386
              IMAGE_FILE_MACHINE_R3000_BE:    0x0160, # MPIS big-endian
              IMAGE_FILE_MACHINE_R3000:       0x0162, # MIPS little-endian
              IMAGE_FILE_MACHINE_R4000:       0x0166, # MIPS little-endian
              IMAGE_FILE_MACHINE_R10000:      0x0168, # MIPS little-endian
              IMAGE_FILE_MACHINE_WCEMIPSV2:   0x0169, # MIPS little-endian WCE v2
              IMAGE_FILE_MACHINE_ALPHA:       0x0184, # Alpha_AXP
              IMAGE_FILE_MACHINE_SH3:         0x01a2, # SH3 little-endian
              IMAGE_FILE_MACHINE_SH3DSP:      0x01a3, # SH3DSP
              IMAGE_FILE_MACHINE_SH3E:        0x01a4, # SH3E little-endian
              IMAGE_FILE_MACHINE_SH4:         0x01a6, # SH4 little-endian
              IMAGE_FILE_MACHINE_SH5:         0x01a8, # SH5
              IMAGE_FILE_MACHINE_ARM:         0x01c0, # ARM Little-Endian
              IMAGE_FILE_MACHINE_THUMB:       0x01c2, # ARM Thumb/Thumb-2 Little-Endian
              IMAGE_FILE_MACHINE_ARMNT:       0x01c4, # ARM Thumb-2 Little-Endian
              IMAGE_FILE_MACHINE_AM33:        0x01d3, # TAM33BD
              IMAGE_FILE_MACHINE_POWERPC:     0x01f0, # IBM PowerPC Little-Endian
              IMAGE_FILE_MACHINE_POWERPCFP:   0x01f1, # POWERPCFP
              IMAGE_FILE_MACHINE_POWERPCX360: 0x01f2, # POWERPC Xbox 360
              IMAGE_FILE_MACHINE_IA64:        0x0200, # Intel 64
              IMAGE_FILE_MACHINE_MIPS16:      0x0266, # MIPS
              IMAGE_FILE_MACHINE_ALPHA64:     0x0284, # ALPHA64
              IMAGE_FILE_MACHINE_MIPSFPU:     0x0366, # MIPS
              IMAGE_FILE_MACHINE_MIPSFPU16:   0x0466, # MIPS
              IMAGE_FILE_MACHINE_AXP64:       0x0284, # AXP64
              IMAGE_FILE_MACHINE_TRICORE:     0x0520, # Infineon
              IMAGE_FILE_MACHINE_CEF:         0x0CEF, # CEF
              IMAGE_FILE_MACHINE_EBC:         0x0EBC, # EFI Byte Code
              IMAGE_FILE_MACHINE_AMD64:       0x8664, # AMD64 (K8)
              IMAGE_FILE_MACHINE_M32R:        0x9041, # M32R little-endian
              IMAGE_FILE_MACHINE_ARM64:       0xAA64, # ARM64 Little-Endian
              IMAGE_FILE_MACHINE_CEE:         0xC0EE, # CEE
            }
  end

  CPUType = Class::new(LibBin::Structure::Enum) do |c|
    c.type = LibBin::Structure::UInt16_LE
    c.map = { CV_CFL_8080:         0x00,
              CV_CFL_8086:         0x01,
              CV_CFL_80286:        0x02,
              CV_CFL_80386:        0x03,
              CV_CFL_80486:        0x04,
              CV_CFL_PENTIUM:      0x05,
              CV_CFL_PENTIUMII:    0x06,
              CV_CFL_PENTIUMIII:   0x07,
              CV_CFL_MIPSR4000:    0x10,
              CV_CFL_MIPS16:       0x11,
              CV_CFL_MIPS32:       0x12,
              CV_CFL_MIPS64:       0x13,
              CV_CFL_MIPSI:        0x14,
              CV_CFL_MIPSII:       0x15,
              CV_CFL_MIPSIII:      0x16,
              CV_CFL_MIPSIV:       0x17,
              CV_CFL_MIPSV:        0x18,
              CV_CFL_M68000:       0x20,
              CV_CFL_M68010:       0x21,
              CV_CFL_M68020:       0x22,
              CV_CFL_M68030:       0x23,
              CV_CFL_M68040:       0x24,
              CV_CFL_ALPHA_21064:  0x30,
              CV_CFL_ALPHA_21164:  0x31,
              CV_CFL_ALPHA_21164A: 0x32,
              CV_CFL_ALPHA_21264:  0x33,
              CV_CFL_ALPHA_21364:  0x34,
              CV_CFL_PPC601:       0x40,
              CV_CFL_PPC603:       0x41,
              CV_CFL_PPC604:       0x42,
              CV_CFL_PPC620:       0x43,
              CV_CFL_PPCFP:        0x44,
              CV_CFL_PPCBE:        0x45,
              CV_CFL_SH3:          0x50,
              CV_CFL_SH3E:         0x51,
              CV_CFL_SH3DSP:       0x52,
              CV_CFL_SH4:          0x53,
              CV_CFL_SHMEDIA:      0x54,
              CV_CFL_ARM3:         0x60,
              CV_CFL_ARM4:         0x61,
              CV_CFL_ARM4T:        0x62,
              CV_CFL_ARM5:         0x63,
              CV_CFL_ARM5T:        0x64,
              CV_CFL_ARM6:         0x65,
              CV_CFL_ARM_XMAC:     0x66,
              CV_CFL_ARM_WMMX:     0x67,
              CV_CFL_ARM7:         0x68,
              CV_CFL_OMNI:         0x70,
              CV_CFL_IA64_1:       0x80,
              CV_CFL_IA64_2:       0x81,
              CV_CFL_CEE:          0x90,
              CV_CFL_AM33:         0xA0,
              CV_CFL_M32R:         0xB0,
              CV_CFL_TRICORE:      0xC0,
              CV_CFL_AMD64:        0xD0,
              CV_CFL_EBC:          0xE0,
              CV_CFL_THUMB:        0xF0,
              CV_CFL_ARMNT:        0xF4,
              CV_CFL_ARM64:        0xF6,
              CV_CFL_D3D11_SHADER: 0x100,
            }
  end

  class DBIHeader < LibBin::Structure
    uint32_le      :verSignature
    uint32_le      :verHdr, expect: 19990903
    uint32_le      :age
    uint16_le      :snGSSyms # Global symbols stream index
    uint16_le      :usVerAll
    #  union {
    #      struct {
    #          USHORT      usVerPdbDllMin : 8; // minor version and
    #          USHORT      usVerPdbDllMaj : 7; // major version and
    #          USHORT      fNewVerFmt     : 1; // flag telling us we have rbld stored elsewhere (high bit of original major version)
    #      } vernew;                           // that built this pdb last.
    #      struct {
    #          USHORT      usVerPdbDllRbld: 4;
    #          USHORT      usVerPdbDllMin : 7;
    #          USHORT      usVerPdbDllMaj : 5;
    #      } verold;
    #      USHORT          usVerAll;
    #  };
    uint16_le      :snPSSyms         # Public symbols stream index
    uint16_le      :usVerPdbDllBuild # Build version of the pdb dll that built this pdb last.
    uint16_le      :snSymRecs        # Symbol records stream index
    uint16_le      :usVerPdbDllRBld  # Rbld version of the pdb dll that built this pdb last.
    uint32_le      :cbGpModi         # Size of rgmodi substream
    uint32_le      :cbSC             # Size of Section Contribution substream
    uint32_le      :cbSecMap         # Size of section map
    uint32_le      :cbFileInfo       # Size of source info
    uint32_le      :cbTSMap          # Size of the Type Server Map substream
    uint32_le      :iMFC             # Index of MFC type server
    uint32_le      :cbDbgHdr         # Size of optional DbgHdr info appended to the end of the stream
    uint32_le      :cbECInfo         # Number of bytes in EC substream, or 0 if EC no EC enabled Mods
    bitfield       :flags, { fIncLink:  1, # true if linked incrmentally (really just if ilink thunks are present)
                             fStripped: 1, # true if PDB::CopyTo stripped the private data out
                             fCTypes:   1, # true if this PDB is using CTypes.
                             unused:   13, # reserved, must be 0.
                           }, size: 16, big: false
    register_field :machine, MachineType
    uint32_le      :rgulReserved, length: 1
  end

  ImageCharacteristics = Class.new(LibBin::Structure::Bitfield) do |c|
    c.type = LibBin::Structure::UInt32_LE
    c.map = { reserved1:              3,
              TYPE_NO_PAD:            1,
              reserved2:              1,
              CNT_CODE:               1,
              CNT_INITIALIZED_DATA:   1,
              CNT_UNINITIALIZED_DATA: 1,
              LNK_OTHER:              1,
              LNK_INFO:               1,
              reserved3:              1,
              LNK_REMOVE:             1,
              LNK_COMDAT:             1,
              reserved4:              1,
              NO_DEFER_SPEC_EXC:      1,
              GPREL:                  1,
              reserved5:              1,
              MEM_PURGEABLE:          1,
              MEM_LOCKED:             1,
              MEM_PRELOAD:            1,
              ALIGN:                  4,
              LNK_NRELOC_OVFL:        1,
              MEM_DISCARDABLE:        1,
              MEM_NOT_CACHED:         1,
              MEM_NOT_PAGED:          1,
              MEM_SHARED:             1,
              MEM_EXECUTE:            1,
              MEM_READ:               1,
              MEM_WRITE:              1,
            }
  end

  class SectionContrib < LibBin::Structure
    uint16_le      :isect
    uint16_le      :pad1#, expect: 0
    int32_le       :off
    uint32_le      :cb
    register_field :characteristics, ImageCharacteristics
    uint16_le      :imod
    uint16_le      :pad2#, expect: 0
    uint32_le      :dwDataCrc
    uint32_le      :dwRelocCrc
  end

  class ECInfo < LibBin::Structure
    uint32_le    :niSrcFile # NI for src file name
    uint32_le    :niPdbFile # NI for path to compiler PDB
  end

  class ModuleInformation < LibBin::Structure
    uint32_le      :pmod
    register_field :sc, SectionContrib      # this module's first section contribution
    bitfield       :flags, { fWritten:   1, # TRUE if mod has been written since DBI opened
                             fECEnabled: 1, # TRUE if mod has EC symbolic information
                             unused:     6, # spare
                             iTSM:       8, # index into TSM list for this mods server
                           }, size: 16, big: false
    uint16_le      :sn                      # SN of module debug info (syms, lines, fpo), or snNil
    uint32_le      :cbSyms                  # size of local symbols debug info in stream sn
    uint32_le      :cbLines                 # size of line number debug info in stream sn
    uint32_le      :cbC13Lines              # size of C13 style line number info in stream sn
    uint16_le      :ifileMac                # number of files contributing to this module
    uint16_le      :pad, expect: 0
    uint32_le      :mpifileichFile          # array [0..ifileMac) of offsets into dbi.bufFilenames
    register_field :ecInfo, ECInfo
    string         :szModule
    string         :szObjFile
  end

  OMFSegDescFlags = Class.new(LibBin::Structure::Bitfield) do |c|
    c.type = LibBin::Structure::UInt16_LE
    c.map = {
      read:                1, # segment is readable
      write:               1, # segment is writable
      execute:             1, # segment is executable
      is_32bits_address:   1, # descriptor describes a 32-bit linear address
      reserved1:           4,
      is_selector:         1, # frame represents a selector
      is_absolute_address: 1, # frame represents an absolute address
      is_group:            1, # descriptor represents a group
      reserved2:           5,
    }
  end

  class OMFSegMapDesc < LibBin::Structure
    register_field :flags, OMFSegDescFlags # descriptor flags
    uint16_le      :ovl                    # logical overlay number
    uint16_le      :group                  # group index into descriptor array
    uint16_le      :frame                  # logical segment index - interpreted via flags
    uint16_le      :iSegName               # byte index of the segment or group name in the sstSegName table, or 0xFFFF
    uint16_le      :iClassName             # byte index of the class name in the sstSegName table, or 0xFFFF
    uint32_le      :phyOff                 # Byte offset of the logical segment within the specified physical segment.
                                           # If group is set in flags, offset is the offset of the group.
    uint32_le      :cbSeg                  # byte count of the segment or group
  end

  class OMFSegMap < LibBin::Structure
    uint16_le      :cSeg    # total number of segment descriptors
    uint16_le      :cSegLog # number of logical segment descriptors
    register_field :rgDesc, OMFSegMapDesc, length: lambda { cSeg } # array of segment descriptors
  end

  class FileInfo < LibBin::Structure
    uint16_le :cMod  # module count, could be too small? should be equal to pdb.dbi_stream.modi.count, but not computed yet
    uint16_le :cFile # file count, could be too small
    uint16_le :modIndices, length: lambda { cMod } # Array of module indices
    uint16_le :modFileCount, length: lambda { cMod }
    uint32_le :fileNameOffset, length: lambda { modFileCount.sum }
    string    :filenames, lambda { __parent.header.cbFileInfo - (2 + 2) - (2 + 2) * cMod - 4 * modFileCount.sum }

    def module_file_name_map
      @module_file_name_map ||= begin
        map = fileNameOffset.uniq.sort.map { |o| [o, filenames[o..-1].unpack("Z*").first] }.to_h
        modFileCount.each_with_index.reduce([[], 0]) { |(arr, off), (c, i)| [arr << [i, fileNameOffset[off...(off+c)].map { |o| map[o] }], off+c] }.first.to_h
      end
    end
  end

  class DbgHdr < LibBin::Structure
    uint16_le :dbgtypeFPO
    uint16_le :dbgtypeException
    uint16_le :dbgtypeFixup
    uint16_le :dbgtypeOmapToSrc
    uint16_le :dbgtypeOmapFromSrc
    uint16_le :dbgtypeSectionHdr
    uint16_le :dbgtypeTokenRidMap
    uint16_le :dbgtypeXdata
    uint16_le :dbgtypePdata
    uint16_le :dbgtypeNewFPO
    uint16_le :dbgtypeSectionHdrOrig
  end

  class DBIStream < LibBin::Structure
    attr_accessor :modi
    register_field :header, DBIHeader
    string         :modi_data, lambda { header.cbGpModi }, condition: lambda { header.cbGpModi > 0 }
    uint32_le      :sc_version, expect: 0xeffe0000 + 19970605, condition: lambda { header.cbSC > 0 }
    register_field :sc, SectionContrib, length: lambda { (header.cbSC - 4)/ 0x1c }, condition: lambda { header.cbSC > 4 }
    register_field :segMap, OMFSegMap, condition: lambda { header.cbSecMap > 4 }
    register_field :fileInfo, FileInfo, condition: lambda { header.cbFileInfo > 0 }
    string         :tsMap_data, lambda { header.cbTSMap }, condition: lambda { header.cbTSMap > 0 }
    string         :ecInfo_data, lambda { header.cbECInfo }, condition: lambda { header.cbECInfo > 0 }
    register_field :dbgHdr, DbgHdr

    def self.load(input, input_big = LibBin::default_big?, *args)
      res = super
      if res.header.cbGpModi > 0
        res.modi = []
        modi_stream = StringIO.new(res.modi_data, "rb")
        while !modi_stream.eof?
          modi_stream.seek(4 - (modi_stream.tell % 4), IO::SEEK_CUR) if modi_stream.tell % 4 != 0
          break if modi_stream.eof?
          res.modi.push(ModuleInformation.load(modi_stream))
        end
      end
      res
    end
  end

  class SuperBlock < LibBin::Structure
    string    :file_magic, 0x20
    uint32_le :block_size
    uint32_le :free_block_map_block
    uint32_le :num_blocks
    uint32_le :num_directory_bytes
    uint32_le :unknown
    uint32_le :block_map_addr
  end

  register_field :super_block, SuperBlock
  uint32_le      :stream_directory_block_map, offset: 'super_block\block_map_addr * super_block\block_size',
                                               count: '(super_block\num_directory_bytes + super_block\block_size - 1) / super_block\block_size'

  attr_accessor :stream_directory
  attr_accessor :streams
  attr_accessor :info_stream
  attr_accessor :names
  attr_accessor :src_header_block
  attr_accessor :tpi_stream
  attr_accessor :dbi_stream

  def self.load(input, input_big = LibBin::default_big?, *args)
    res = super
    res.stream_directory = StreamDirectory::load(read_stream(input, res.super_block.num_directory_bytes, res.super_block.block_size, res.stream_directory_block_map), input_big, res)
    res.streams = res.stream_directory.num_streams.times.map { |i| read_stream(input, res.stream_directory.stream_sizes[i], res.super_block.block_size, res.stream_directory.stream_blocks[i]) }
    res.info_stream = InfoStream::load(res.streams[1]) if res.streams.size >= 2
    if res.info_stream
      if (index = res.info_stream.named_stream_map.to_h["/names"]) && res.streams[index].size > 0
        res.names = NameStream::load(res.streams[index])
      end
      if (index = res.info_stream.named_stream_map.to_h["/src/headerblock"]) && res.streams[index].size > 0
        res.src_header_block = SrcHeaderBlock::load(res.streams[index])
      end
    end
    if res.streams[2].size > 0
      res.tpi_stream = TpiStream.load(res.streams[2])
    end
    if res.streams[3].size > 0
      res.dbi_stream = DBIStream.load(res.streams[3])
    end
    res
  end
end

def open_bin(filename, &block)
  File::open(filename, 'rb', &block)
end

open_bin(ARGV[0]) do |f|
  pdb = PDBFile::load(f)
  pp pdb.info_stream.named_stream_map.to_h
  pp pdb.src_header_block
  pp pdb.tpi_stream.header.instance_variables.map { |n| [n, pdb.tpi_stream.header.instance_variable_get(n)] }.to_h
  pp pdb.tpi_stream.records.map(&:kind).uniq
  pp pdb.tpi_stream.records.count
  pp pdb.tpi_stream.records.filter_map(&:field).count
  pp pdb.dbi_stream.header.instance_variables.map { |v| [v, pdb.dbi_stream.header.instance_variable_get(v)]}.to_h
  pp pdb.dbi_stream.modi.count #.map { |i| i.instance_variables.map { |v| [v, i.instance_variable_get(v)] }.to_h }
  pp pdb.dbi_stream.sc.count #.map { |i| i.instance_variables.map { |v| [v, i.instance_variable_get(v)] }.to_h }
  pp pdb.dbi_stream.segMap.rgDesc.count #.map { |i| i.instance_variables.map { |v| [v, i.instance_variable_get(v)] }.to_h }
  pp pdb.dbi_stream.fileInfo.module_file_name_map.count #filenames #instance_variables.map { |v| [v, pdb.dbi_stream.fileInfo.instance_variable_get(v)] }.to_h
  pp pdb.dbi_stream.dbgHdr.instance_variables.map { |v| [v, pdb.dbi_stream.dbgHdr.instance_variable_get(v)] }.to_h
end
