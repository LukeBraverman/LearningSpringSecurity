package com.learningspringsecurity.demospringsecurity.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Ana Smith")

    );

    @GetMapping
    public List<Student> getAllStudents() {
        System.out.println("Get all students");
        return  STUDENTS;
    }
    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("Register new student.");
        System.out.println(student);
    }
    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("Delete all students");
        System.out.println(studentId);
    }
    @PutMapping(path="{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student) {
        System.out.println("Update all students");
        System.out.println(String.format("%s %s",studentId,student));
    }

}
