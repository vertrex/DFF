namespace "fragments"
  Node:
    class Node extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
        @tablist = null
#        @table = $('<table>').append($('<tr>'))
        @table = $('<div>').addClass('container')
        if @json.thumb
          @parseThumb()
        @parseAttributes()

      render: (root) ->
        super
        @html.append(@table)
        $('nav-tabs#' + @id + ' a:first').tab('show')
#        @tablist.tab('show')

      parseThumb: () ->
        td = $('<td>').attr('width', '10%')
        if @json.thumb
          link = $('<a>').attr('href', @json.file)
          thumb = $('<img>')
            .attr('src', @json.thumb)
          link.append(thumb)
          td.append(link)
        @table.append(td)

      parseAttributes: () ->
        if @json.row_details['data']
#          td = $('<td>').attr('width', '90%')
          @tablist = $('<ul>').addClass('nav nav-tabs').attr('id', @id)
          tabcontent = $('<div>').addClass('tab-content')
          counter = 0
          for attr, values of @json.row_details['data']
            item = $('<li>')
            if counter is 0
              item.addClass('active')
            item.append($('<a>')
              .attr('data-toggle', 'tab')
              .attr('href', '#' + @id + attr)
              .append(attr)
            )
            content = $('<div>').addClass('tab-pane').attr('id', @id + attr)
            if counter is 0
              content.addClass('active')
            attrtab = $('<table>').addClass('table')
            attrtab.append($('<thead>')
              .append($('<tr>')
                .append($('<th>')
                  .append('Attribute'))
                .append($('<th>')
                  .append('Values'))))
            tbody = $('<tbody>')
            for name, value of values
              tr = $('<tr>')
              tr.append($('<td>').append(name))
              tr.append($('<td>').append(value))
              tbody.append(tr)  
            attrtab.append(tbody)
            content.append(attrtab)
            counter++
            @tablist.append(item)
            tabcontent.append(content)
          @table.append(@tablist)
          @table.append(tabcontent)

  Tab:
    class Tab extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
#        console.log
        @container = $('<div>').addClass('container')
        @fmanager = new fragments.Manager()
        @tablist = null
        @frags = []
        @parseData()

      render: (root) ->
        super
        @html.append(@container)
        $('nav-tabs#' + @id + ' a:first').tab('show')
#        @tablist.tab('show')
        count = 0
        for f  in @fmanager.fragments
          f.render @frags[count]
          count++

      parseData: () ->
        if @json.data
          td = $('<div>').addClass('container')
          @tablist = $('<ul>').addClass('nav nav-tabs').attr('id', @id)
          tabcontent = $('<div>').addClass('tab-content')
          counter = 0
          for title, fragment of @json.data
            item = $('<li>')
            if counter is 0
              item.addClass('active')
            item.append($('<a>')
              .attr('data-toggle', 'tab')
              .attr('href', '#' + @id + title)
              .append(title)
            )
            content = $('<div>').addClass('tab-pane').attr('id', @id + title)
            if counter is 0
              content.addClass('active')
#            console.log fragment
            frag = @fmanager.create(fragment)
            @frags.push content
            counter++
            @tablist.append(item)
            tabcontent.append(content)

          td.append(@tablist)
          td.append(tabcontent)
          @container.append(td)

