package com.hollybee.encodesection;

import com.hollybee.encodesection.ElfType32.Elf32_Sym;
import com.hollybee.encodesection.ElfType32.elf32_phdr;
import com.hollybee.encodesection.ElfType32.elf32_shdr;

public class AddSection {
    public static String addSectionName = ".mytext";

    public static ElfType32 type_32 = new ElfType32();

    //public static String newSectionName = ".hollybee";
    public static String newSectionName;

    public static int newSectionNameLen = 0x10;
    //public static int newSectionSize = 1000;
    public static int newSectionSize;

    public static int sectionHeaderSize = 40;
    public static int sectionSizeOffset = 20;
    public static int elfHeaderSectionCountIndex = 48;
    public static int programFileSizeIndex = 16;

    public static int programHeaderOffset;
    public static short programHeaderSize;
    public static int sectionHeaderOffset;
    public static short stringSectionInSectionTableIndex;
    public static int stringSectionOffset;
    public static int lastLoadVaddr;
    public static int lastLoadMemsize;
    public static int addSectionStartAddr;

    public static void addSectionMain(String filePath, String savePath){
        byte[] fileByteArys = Utils.readFile(filePath);

        if(fileByteArys == null){
            System.out.println("read file byte failed...");
            return;
        }

        /**
         * 先解析so文件
         * 然后初始化AddSection中的一些信息
         * 最后在AddSection
         */
        parseSo(fileByteArys);

        initial();

        findLastLoadInPhIndex();

        System.out.println(addSectionStartAddr);

        fileByteArys = addSection(fileByteArys);

        //type_32.renew();
        //parseSo(fileByteArys);

        Utils.saveFile(savePath, fileByteArys);
    }

    /**
     * 在运行addSection之前进行的初始化
     */
    public static void initial(){

        programHeaderOffset = Utils.byte2Int(type_32.hdr.e_phoff);
        programHeaderSize = Utils.byte2Short(type_32.hdr.e_phentsize);

        sectionHeaderOffset = Utils.byte2Int(type_32.hdr.e_shoff);
        stringSectionInSectionTableIndex = Utils.byte2Short(type_32.hdr.e_shstrndx);
        stringSectionOffset = Utils.byte2Int(type_32.shdrList.get(stringSectionInSectionTableIndex).sh_offset);

        lastLoadVaddr = Utils.byte2Int(type_32.phdrList.get(findLastLoadInPhIndex()).p_vaddr);
        lastLoadMemsize = Utils.byte2Int(type_32.phdrList.get(findLastLoadInPhIndex()).p_memsz);
        addSectionStartAddr = Utils.align(lastLoadVaddr + lastLoadMemsize, 0x1000);

    }


    /**
     * 由于LOAD程序段是按照p_vaddr的值做升序排列的，所以顺序遍历得到的就是last LOAD程序段的index
     * @return lastIndex
     */
    public static int findLastLoadInPhIndex(){
        int lastIndex = 0;
        for (int i = 0; i < type_32.phdrList.size(); i ++){
            if (Utils.byte2Int(type_32.phdrList.get(i).p_type) == 1){
                lastIndex = i;
            }
        }
        return lastIndex;
    }

    public static int findFirstLoadInPhIndex(){
        int firstIndex = 0;
        for (int i = 0; i < type_32.phdrList.size(); i ++){
            if (Utils.byte2Int(type_32.phdrList.get(i).p_type) == 1){
                firstIndex = i;
                break;
            }
        }
        return firstIndex;
    }

    /**
     * 在fileByteArys后面添加新的section
     * @param fileByteArys
     */
    public static byte[] addSection(byte[] fileByteArys){

        //byte[] newfile
        //首先，在末尾添加新的section header
        fileByteArys = addSectionHeader(fileByteArys);

        //然后，在文件末尾添加空白段+增加段名String
        fileByteArys = addNewSectionForFileEnd(fileByteArys);

        //然后，修改.strtab段的长度
        fileByteArys = changeStrtabLen(fileByteArys);

        //再次，修改elf头部总的section的总数信息
        fileByteArys = changeElfHeaderSectionCount(fileByteArys);

        //最后，修改Program Header中的信息
        //把新增的段内容加入到LOAD Segement中
        //就是修改第一个LOAD类型的Segement的filesize和memsize为文件的总长度
        fileByteArys = changeProgramHeaderLoadInfo(fileByteArys);

        return fileByteArys;
    }


    /**
     * 添加section header信息
     * 原理：
     * 找到String Section的位置，然后获取他偏移值
     * 将section添加到文件末尾
     */
    public static byte[] addSectionHeader(byte[] src){
        /**
         *  public byte[] sh_name = new byte[4];
         public byte[] sh_type = new byte[4];
         public byte[] sh_flags = new byte[4];
         public byte[] sh_addr = new byte[4];
         public byte[] sh_offset = new byte[4];
         public byte[] sh_size = new byte[4];
         public byte[] sh_link = new byte[4];
         public byte[] sh_info = new byte[4];
         public byte[] sh_addralign = new byte[4];
         public byte[] sh_entsize = new byte[4];
         */
        byte[] newHeader = new byte[sectionHeaderSize];

        //构建一个New Section Header
        newHeader = Utils.replaceByteAry(newHeader, 0, Utils.int2Byte(addSectionStartAddr - stringSectionOffset));
        newHeader = Utils.replaceByteAry(newHeader, 4, Utils.int2Byte(ElfType32.SHT_PROGBITS));//type=PROGBITS
        newHeader = Utils.replaceByteAry(newHeader, 8, Utils.int2Byte(ElfType32.SHF_ALLOC));
        newHeader = Utils.replaceByteAry(newHeader, 12, Utils.int2Byte(addSectionStartAddr + newSectionNameLen));
        newHeader = Utils.replaceByteAry(newHeader, 16, Utils.int2Byte(addSectionStartAddr + newSectionNameLen));
        newHeader = Utils.replaceByteAry(newHeader, 20, Utils.int2Byte(newSectionSize));
        newHeader = Utils.replaceByteAry(newHeader, 24, Utils.int2Byte(0));
        newHeader = Utils.replaceByteAry(newHeader, 28, Utils.int2Byte(0));
        newHeader = Utils.replaceByteAry(newHeader, 32, Utils.int2Byte(4));
        newHeader = Utils.replaceByteAry(newHeader, 36, Utils.int2Byte(0));

        //在末尾增加Section
        byte[] newSrc = new byte[src.length + newHeader.length];
        newSrc = Utils.replaceByteAry(newSrc, 0, src);
        newSrc = Utils.replaceByteAry(newSrc, src.length, newHeader);

        return newSrc;
    }


    /**
     * 在文件末尾添加空白段+增加段名String
     * @param src
     * @return
     */
    public static byte[] addNewSectionForFileEnd(byte[] src){

        byte[] stringByte = newSectionName.getBytes();
        byte[] newSection = new byte[newSectionSize + newSectionNameLen];
        newSection = Utils.replaceByteAry(newSection, 0, stringByte);
        //新建一个byte[]
        byte[] newSrc = new byte[addSectionStartAddr + newSection.length];
        newSrc = Utils.replaceByteAry(newSrc, 0, src);//复制之前的文件src
        newSrc = Utils.replaceByteAry(newSrc, addSectionStartAddr, newSection);//复制section
        return newSrc;
    }


    /**
     * 修改.strtab段的长度
     */
    public static byte[] changeStrtabLen(byte[] src){

        //获取到String的size字段的开始位置
        int size_index = sectionHeaderOffset + (stringSectionInSectionTableIndex) * sectionHeaderSize + sectionSizeOffset;

        //多了一个Section Header + 多了一个Section的name的16个字节
        byte[] newLen_ary = Utils.int2Byte(addSectionStartAddr - stringSectionOffset + newSectionNameLen);
        src = Utils.replaceByteAry(src, size_index, newLen_ary);
        return src;
    }

    /**
     * 修改elf头部总的section的总数信息
     */
    public static byte[] changeElfHeaderSectionCount(byte[] src){
        byte[] count = Utils.copyBytes(src, elfHeaderSectionCountIndex, 2);
        short counts = Utils.byte2Short(count);
        counts++;
        count = Utils.short2Byte(counts);
        src = Utils.replaceByteAry(src, elfHeaderSectionCountIndex, count);
        return src;
    }

    /**
     * 修改Program Header中的信息
     * 把新增的段内容加入到LOAD Segement中
     * 就是修改第一个LOAD类型的Segement的filesize和memsize为文件的总长度
     */
    public static byte[] changeProgramHeaderLoadInfo(byte[] src){
        //寻找到LOAD类型的Segement位置
        int offset = programHeaderOffset + programHeaderSize * findFirstLoadInPhIndex() + programFileSizeIndex;
        //file size字段
        byte[] fileSize = Utils.int2Byte(src.length);
        src = Utils.replaceByteAry(src, offset, fileSize);
        //mem size字段
        offset = offset + 4;
        byte[] memSize = Utils.int2Byte(src.length);
        src = Utils.replaceByteAry(src, offset, memSize);
        //flag字段
        offset = offset + 4;
        byte[] flag = Utils.int2Byte(5);
        src = Utils.replaceByteAry(src, offset, flag);
        return src;
    }


    private static void parseSo(byte[] fileByteArys){
        //读取头部内容
        System.out.println("+++++++++++++++++++Elf Header+++++++++++++++++");
        parseHeader(fileByteArys, 0);
        System.out.println("header:\n"+type_32.hdr);

        //读取程序头信息
        System.out.println();
        System.out.println("+++++++++++++++++++Program Header+++++++++++++++++");
        int p_header_offset = Utils.byte2Int(type_32.hdr.e_phoff);
        parseProgramHeaderList(fileByteArys, p_header_offset);
        type_32.printPhdrList();

        //读取段头信息
        System.out.println();
        System.out.println("+++++++++++++++++++Section Header++++++++++++++++++");
        int s_header_offset = Utils.byte2Int(type_32.hdr.e_shoff);
        parseSectionHeaderList(fileByteArys, s_header_offset);
        type_32.printShdrList();

        //这种方式获取所有的Section的name
		/*byte[] names = Utils.copyBytes(fileByteArys, offset, size);
		String str = new String(names);
		byte NULL = 0;//字符串的结束符
		StringTokenizer st = new StringTokenizer(str, new String(new byte[]{NULL}));
		System.out.println( "Token Total: " + st.countTokens() );
		while(st.hasMoreElements()){
			System.out.println(st.nextToken());
		}
		System.out.println("");*/

		/*//读取符号表信息(Symbol Table)
		System.out.println();
		System.out.println("+++++++++++++++++++Symbol Table++++++++++++++++++");
		//这里需要注意的是：在Elf表中没有找到SymbolTable的数目，但是我们仔细观察Section中的Type=DYNSYM段的信息可以得到，这个段的大小和偏移地址，而SymbolTable的结构大小是固定的16个字节
		//那么这里的数目=大小/结构大小
		//首先在SectionHeader中查找到dynsym段的信息
		int offset_sym = 0;
		int total_sym = 0;
		for(elf32_shdr shdr : type_32.shdrList){
			if(Utils.byte2Int(shdr.sh_type) == ElfType32.SHT_DYNSYM){
				total_sym = Utils.byte2Int(shdr.sh_size);
				offset_sym = Utils.byte2Int(shdr.sh_offset);
				break;
			}
		}
		int num_sym = total_sym / 16;
		System.out.println("sym num="+num_sym);
		parseSymbolTableList(fileByteArys, num_sym, offset_sym);
		type_32.printSymList();

		//读取字符串表信息(String Table)
		System.out.println();
		System.out.println("+++++++++++++++++++Symbol Table++++++++++++++++++");
		//这里需要注意的是：在Elf表中没有找到StringTable的数目，但是我们仔细观察Section中的Type=STRTAB段的信息，可以得到，这个段的大小和偏移地址，但是我们这时候我们不知道字符串的大小，所以就获取不到数目了
		//这里我们可以查看Section结构中的name字段：表示偏移值，那么我们可以通过这个值来获取字符串的大小
		//可以这么理解：当前段的name值 减去 上一段的name的值 = (上一段的name字符串的长度)
		//首先获取每个段的name的字符串大小
		int prename_len = 0;
		int[] lens = new int[type_32.shdrList.size()];
		int total = 0;
		for(int i=0;i<type_32.shdrList.size();i++){
			if(Utils.byte2Int(type_32.shdrList.get(i).sh_type) == ElfType32.SHT_STRTAB){
				int curname_offset = Utils.byte2Int(type_32.shdrList.get(i).sh_name);
				lens[i] = curname_offset - prename_len - 1;
				if(lens[i] < 0){
					lens[i] = 0;
				}
				total += lens[i];
				System.out.println("total:"+total);
				prename_len = curname_offset;
				//这里需要注意的是，最后一个字符串的长度，需要用总长度减去前面的长度总和来获取到
				if(i == (lens.length - 1)){
					System.out.println("size:"+Utils.byte2Int(type_32.shdrList.get(i).sh_size));
					lens[i] = Utils.byte2Int(type_32.shdrList.get(i).sh_size) - total - 1;
				}
			}
		}
		for(int i=0;i<lens.length;i++){
			System.out.println("len:"+lens[i]);
		}
		//上面的那个方法不好，我们发现StringTable中的每个字符串结束都会有一个00(传说中的字符串结束符)，那么我们只要知道StringTable的开始位置，然后就可以读取到每个字符串的值了
       */
    }

    /**
     * 解析Elf的头部信息
     * @param header
     */
    private static void  parseHeader(byte[] header, int offset){
        if(header == null){
            System.out.println("header is null");
            return;
        }
        /**
         *  public byte[] e_ident = new byte[16];
         public short e_type;
         public short e_machine;
         public int e_version;
         public int e_entry;
         public int e_phoff;
         public int e_shoff;
         public int e_flags;
         public short e_ehsize;
         public short e_phentsize;
         public short e_phnum;
         public short e_shentsize;
         public short e_shnum;
         public short e_shstrndx;
         */
        type_32.hdr.e_ident = Utils.copyBytes(header, 0, 16);//魔数
        type_32.hdr.e_type = Utils.copyBytes(header, 16, 2);
        type_32.hdr.e_machine = Utils.copyBytes(header, 18, 2);
        type_32.hdr.e_version = Utils.copyBytes(header, 20, 4);
        type_32.hdr.e_entry = Utils.copyBytes(header, 24, 4);
        type_32.hdr.e_phoff = Utils.copyBytes(header, 28, 4);
        type_32.hdr.e_shoff = Utils.copyBytes(header, 32, 4);
        type_32.hdr.e_flags = Utils.copyBytes(header, 36, 4);
        type_32.hdr.e_ehsize = Utils.copyBytes(header, 40, 2);
        type_32.hdr.e_phentsize = Utils.copyBytes(header, 42, 2);
        type_32.hdr.e_phnum = Utils.copyBytes(header, 44,2);
        type_32.hdr.e_shentsize = Utils.copyBytes(header, 46,2);
        type_32.hdr.e_shnum = Utils.copyBytes(header, 48, 2);
        type_32.hdr.e_shstrndx = Utils.copyBytes(header, 50, 2);
    }

    /**
     * 解析程序头信息
     * @param header
     */
    public static void parseProgramHeaderList(byte[] header, int offset){
        int header_size = 32;//32个字节
        int header_count = Utils.byte2Short(type_32.hdr.e_phnum);//头部的个数
        byte[] des = new byte[header_size];
        for(int i=0;i<header_count;i++){
            System.arraycopy(header, i*header_size + offset, des, 0, header_size);
            type_32.phdrList.add(parseProgramHeader(des));
        }
    }

    private static elf32_phdr parseProgramHeader(byte[] header){
        /**
         *  public int p_type;
         public int p_offset;
         public int p_vaddr;
         public int p_paddr;
         public int p_filesz;
         public int p_memsz;
         public int p_flags;
         public int p_align;
         */
        ElfType32.elf32_phdr phdr = new ElfType32.elf32_phdr();
        phdr.p_type = Utils.copyBytes(header, 0, 4);
        phdr.p_offset = Utils.copyBytes(header, 4, 4);
        phdr.p_vaddr = Utils.copyBytes(header, 8, 4);
        phdr.p_paddr = Utils.copyBytes(header, 12, 4);
        phdr.p_filesz = Utils.copyBytes(header, 16, 4);
        phdr.p_memsz = Utils.copyBytes(header, 20, 4);
        phdr.p_flags = Utils.copyBytes(header, 24, 4);
        phdr.p_align = Utils.copyBytes(header, 28, 4);
        return phdr;

    }

    /**
     * 解析段头信息内容
     */
    public static void parseSectionHeaderList(byte[] header, int offset){
        int header_size = 40;//40个字节
        int header_count = Utils.byte2Short(type_32.hdr.e_shnum);//头部的个数
        byte[] des = new byte[header_size];
        for(int i=0;i<header_count;i++){
            System.arraycopy(header, i*header_size + offset, des, 0, header_size);
            type_32.shdrList.add(parseSectionHeader(des));
        }
    }

    private static elf32_shdr parseSectionHeader(byte[] header){
        ElfType32.elf32_shdr shdr = new ElfType32.elf32_shdr();
        /**
         *  public byte[] sh_name = new byte[4];
         public byte[] sh_type = new byte[4];
         public byte[] sh_flags = new byte[4];
         public byte[] sh_addr = new byte[4];
         public byte[] sh_offset = new byte[4];
         public byte[] sh_size = new byte[4];
         public byte[] sh_link = new byte[4];
         public byte[] sh_info = new byte[4];
         public byte[] sh_addralign = new byte[4];
         public byte[] sh_entsize = new byte[4];
         */
        shdr.sh_name = Utils.copyBytes(header, 0, 4);
        shdr.sh_type = Utils.copyBytes(header, 4, 4);
        shdr.sh_flags = Utils.copyBytes(header, 8, 4);
        shdr.sh_addr = Utils.copyBytes(header, 12, 4);
        shdr.sh_offset = Utils.copyBytes(header, 16, 4);
        shdr.sh_size = Utils.copyBytes(header, 20, 4);
        shdr.sh_link = Utils.copyBytes(header, 24, 4);
        shdr.sh_info = Utils.copyBytes(header, 28, 4);
        shdr.sh_addralign = Utils.copyBytes(header, 32, 4);
        shdr.sh_entsize = Utils.copyBytes(header, 36, 4);
        return shdr;
    }

    /**
     * 解析Symbol Table内容
     */
    public static void parseSymbolTableList(byte[] header, int header_count, int offset){
        int header_size = 16;//16个字节
        byte[] des = new byte[header_size];
        for(int i=0;i<header_count;i++){
            System.arraycopy(header, i*header_size + offset, des, 0, header_size);
            type_32.symList.add(parseSymbolTable(des));
        }
    }

    private static ElfType32.Elf32_Sym parseSymbolTable(byte[] header){
        /**
         *  public byte[] st_name = new byte[4];
         public byte[] st_value = new byte[4];
         public byte[] st_size = new byte[4];
         public byte st_info;
         public byte st_other;
         public byte[] st_shndx = new byte[2];
         */
        Elf32_Sym sym = new Elf32_Sym();
        sym.st_name = Utils.copyBytes(header, 0, 4);
        sym.st_value = Utils.copyBytes(header, 4, 4);
        sym.st_size = Utils.copyBytes(header, 8, 4);
        sym.st_info = header[12];
        //FIXME 这里有一个问题，就是这个字段读出来的值始终是0
        sym.st_other = header[13];
        sym.st_shndx = Utils.copyBytes(header, 14, 2);
        return sym;
    }


}
