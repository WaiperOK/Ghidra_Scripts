# -*- coding: utf-8 -*-
# Exports the decompiled code AND assembly listing of all defined functions to separate files.
# @author Ruslan based on Ghidra API examples
# @category Export
# @keybinding
# @menupath
# @toolbar

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os
import io 

def run():
    """Runs the script."""
    ifc = None 
    try:
     
        print("Setting up Decompiler...")
        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)

        if not ifc.openProgram(currentProgram):
            print("Decompiler Error: " + ifc.getLastMessage())
            popup("Decompiler Error: " + ifc.getLastMessage())
            return

        try:
            
            c_output_file = askFile("Выберите файл для сохранения ДЕКОМПИЛИРОВАННОГО C-кода", "Сохранить C")
            if c_output_file is None:
                print("Export cancelled by user (C file selection).")
                return

  
            asm_output_file = askFile("Выберите файл для сохранения АССЕМБЛЕРНОГО листинга", "Сохранить Asm")
            if asm_output_file is None:
                print("Export cancelled by user (Asm file selection).")
                return

            print("Will export Decompiled C code to: " + c_output_file.absolutePath)
            print("Will export Assembly Listing to: " + asm_output_file.absolutePath)

        except Exception as e:
            print("Error selecting file: {}".format(e))
            popup("Error selecting file: {}".format(e))
            return

       
        num_funcs_exported = 0
        num_funcs_failed_c = 0
        num_funcs_failed_asm = 0
        function_manager = currentProgram.getFunctionManager()
        listing = currentProgram.getListing() # Получаем объект листинга
        defined_functions = [f for f in function_manager.getFunctions(True) if not f.isExternal()]

        print("Found {} defined functions to export.".format(len(defined_functions)))

        
        with io.open(c_output_file.absolutePath, "w", encoding='utf-8') as c_outfile, \
             io.open(asm_output_file.absolutePath, "w", encoding='utf-8') as asm_outfile:

            for func in defined_functions:
                func_name = func.getName()
                func_addr = func.getEntryPoint()
                print("Processing function: {} at {}".format(func_name, func_addr))
                monitor.setMessage("Processing: " + func_name)

                if monitor.isCancelled():
                    print("Export cancelled by user during processing.")
                    break

             
                decompiled_code = None
                try:
                    results = ifc.decompileFunction(func, 60, monitor)
                    markup = None
                    if results is not None and results.decompileCompleted():
                        markup = results.getCCodeMarkup()
                        if markup is not None:
                            decompiled_code = markup.toString()
                        else:
                            print("  WARN (C): Failed to get C markup for {}".format(func_name))
                    else:
                         print("  ERROR (C): Decompilation failed for {}: {}".format(func_name, results.getErrorMessage() if results else "Unknown error"))

                
                    c_outfile.write(u"//----------------------------------------------------------\n")
                    c_outfile.write(u"// FUNCTION (Decompiled C): {} @ {}\n".format(func_name, func_addr))
                    c_outfile.write(u"//----------------------------------------------------------\n")
                    if decompiled_code:
                        if isinstance(decompiled_code, str): outfile.write(unicode(decompiled_code))
                        else: outfile.write(decompiled_code)
                        c_outfile.write(u"\n\n")
                        
                    else:
                        c_outfile.write(u"// Decompilation failed or produced no C output.\n\n")
                        num_funcs_failed_c += 1

                except Exception as e_c:
                    print("  EXCEPTION during C decompilation of {}: {}".format(func_name, e_c))
                    c_outfile.write(u"//----------------------------------------------------------\n")
                    c_outfile.write(u"// FUNCTION (Decompiled C): {} @ {}\n".format(func_name, func_addr))
                    c_outfile.write(u"//----------------------------------------------------------\n")
                    c_outfile.write(u"// EXCEPTION during C decompilation: {}\n\n".format(e_c))
                    num_funcs_failed_c += 1


                
                assembly_exported = False
                try:
                    asm_outfile.write(u"//----------------------------------------------------------\n")
                    asm_outfile.write(u"// FUNCTION (Assembly): {} @ {}\n".format(func_name, func_addr))
                    asm_outfile.write(u"//----------------------------------------------------------\n")

                    
                    addrSet = func.getBody()
                  
                    codeUnits = listing.getCodeUnits(addrSet, True)

                   
                    count = 0
                    for codeUnit in codeUnits:
                        if monitor.isCancelled(): break 
                        line = codeUnit.toString()
                        if isinstance(line, str): asm_outfile.write(unicode(line) + u"\n")
                        else: asm_outfile.write(line + u"\n")
                        count += 1

                    if count > 0:
                       assembly_exported = True 

                    asm_outfile.write(u"\n\n")

                except Exception as e_asm:
                    print("  EXCEPTION during Assembly export of {}: {}".format(func_name, e_asm))
                    asm_outfile.write(u"// EXCEPTION during Assembly export: {}\n\n".format(e_asm))
                    num_funcs_failed_asm += 1

               
                if decompiled_code is not None and assembly_exported:
                    num_funcs_exported += 1
                elif assembly_exported and decompiled_code is None and num_funcs_failed_c > 0:
                   
                     pass 

                if monitor.isCancelled():
                    print("Export cancelled by user during processing.")
                    break 

        if not monitor.isCancelled():
            print("----------------------------------------------------------")
            print("Export Finished.")
            print("Functions processed: {}".format(len(defined_functions)))
            print("Successfully exported (both C and Asm likely): {}".format(num_funcs_exported))
            print("Failed C Decompilation: {}".format(num_funcs_failed_c))
            print("Failed Assembly Export: {}".format(num_funcs_failed_asm))
            print("C Output written to: {}".format(c_output_file.absolutePath))
            print("Asm Output written to: {}".format(asm_output_file.absolutePath))
            popup("Export complete!\nSee console for details.")

    except Exception as e:
        print("General script error: {}".format(e))
        popup("General script error: {}".format(e))

    finally:
    
        if ifc is not None:
            ifc.dispose()
            print("Decompiler disposed.")


run()
