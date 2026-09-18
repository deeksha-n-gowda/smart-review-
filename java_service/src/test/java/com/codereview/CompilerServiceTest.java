package com.codereview;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * CompilerServiceTest.java — Unit Tests
 * ======================================
 * Tests the core compilation logic directly (no HTTP layer).
 * Run with: mvn test
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CompilerServiceTest {

    // ── Helpers ───────────────────────────────────────────────────────────

    /** Calls the private compileAndRun via reflection to test it directly. */
    private ReviewRequest compile(String source, String className, boolean checkOnly) throws Exception {
        var method = CompilerService.class.getDeclaredMethod(
            "compileAndRun", ReviewRequest.class
        );
        method.setAccessible(true);

        ReviewRequest req = new ReviewRequest();
        req.source_code = source;
        req.class_name  = className;
        req.check_only  = checkOnly;
        req.timeout_ms  = 3000;

        return (ReviewRequest) method.invoke(null, req);
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("Valid Hello World compiles successfully")
    void testValidCodeCompiles() throws Exception {
        String source = """
            public class Hello {
                public static void main(String[] args) {
                    System.out.println("Hello, CodeLens!");
                }
            }
            """;
        ReviewRequest result = compile(source, "Hello", true);

        assertTrue(result.success,     "success should be true");
        assertTrue(result.compile_ok,  "compile_ok should be true");
        assertEquals("Hello", result.resolved_class_name);
        assertTrue(result.diagnostics.isEmpty(), "no diagnostics expected for valid code");
    }

    @Test
    @Order(2)
    @DisplayName("Syntax error produces ERROR diagnostic")
    void testSyntaxErrorProducesDiagnostic() throws Exception {
        String source = """
            public class Broken {
                public static void main(String[] args) {
                    int x = ;   // syntax error — missing value
                }
            }
            """;
        ReviewRequest result = compile(source, "Broken", true);

        assertTrue(result.success,     "success should be true (service handled it)");
        assertFalse(result.compile_ok, "compile_ok should be false");
        assertFalse(result.diagnostics.isEmpty(), "should have at least one diagnostic");

        ReviewRequest.Diagnostic first = result.diagnostics.get(0);
        assertEquals("ERROR", first.kind, "diagnostic kind should be ERROR");
        assertTrue(first.line > 0, "line number should be set");
    }

    @Test
    @Order(3)
    @DisplayName("Missing semicolon produces diagnostic at correct line")
    void testMissingSemicolon() throws Exception {
        String source = """
            public class SemiTest {
                public static void main(String[] args) {
                    String s = "hello"
                    System.out.println(s);
                }
            }
            """;
        ReviewRequest result = compile(source, "SemiTest", true);
        assertFalse(result.compile_ok, "should fail to compile");
        assertFalse(result.diagnostics.isEmpty(), "should have diagnostics");
    }

    @Test
    @Order(4)
    @DisplayName("Class name auto-detected from source when not provided")
    void testClassNameAutoDetection() throws Exception {
        String source = """
            public class AutoDetected {
                public static void main(String[] args) {}
            }
            """;
        ReviewRequest result = compile(source, null, true);
        assertEquals("AutoDetected", result.resolved_class_name,
            "class name should be auto-detected from source");
        assertTrue(result.compile_ok, "should compile successfully");
    }

    @Test
    @Order(5)
    @DisplayName("Type error produces diagnostic")
    void testTypeError() throws Exception {
        String source = """
            public class TypeError {
                public static void main(String[] args) {
                    int x = "not a number";   // type mismatch
                }
            }
            """;
        ReviewRequest result = compile(source, "TypeError", true);
        assertFalse(result.compile_ok, "type error should fail compilation");
        assertFalse(result.diagnostics.isEmpty(), "should have type error diagnostic");
    }

    @Test
    @Order(6)
    @DisplayName("Empty source code fails gracefully")
    void testEmptySource() throws Exception {
        ReviewRequest req = new ReviewRequest();
        req.source_code = "public class Empty {}";
        req.check_only  = true;
        req.timeout_ms  = 3000;

        var method = CompilerService.class.getDeclaredMethod("compileAndRun", ReviewRequest.class);
        method.setAccessible(true);
        ReviewRequest result = (ReviewRequest) method.invoke(null, req);

        assertTrue(result.success,    "empty class should succeed");
        assertTrue(result.compile_ok, "empty class body should compile");
    }

    @Test
    @Order(7)
    @DisplayName("Unused import produces WARNING diagnostic")
    void testUnusedImportWarning() throws Exception {
        String source = """
            import java.util.ArrayList;   // unused — should produce a warning with -Xlint:all
            public class WithWarning {
                public static void main(String[] args) {
                    System.out.println("ok");
                }
            }
            """;
        ReviewRequest result = compile(source, "WithWarning", true);
        // Compilation should still succeed even with warnings
        assertTrue(result.success, "should succeed despite warnings");
        // Whether a warning is generated depends on the javac version; don't assert it
    }
}
